const std = @import("std");
const posix = std.posix;

pub const TcpListener = struct {
    fd: posix.socket_t,
    address: std.net.Address,

    pub fn init(listen_addr: [4]u8, port: u16) !TcpListener {
        const address = std.net.Address.initIp4(listen_addr, port);

        const fd = try posix.socket(
            posix.AF.INET,
            posix.SOCK.STREAM,
            posix.IPPROTO.TCP,
        );
        errdefer posix.close(fd);

        // Set SO_REUSEADDR to allow quick restarts
        try posix.setsockopt(
            fd,
            posix.SOL.SOCKET,
            posix.SO.REUSEADDR,
            &std.mem.toBytes(@as(c_int, 1)),
        );

        try posix.bind(fd, &address.any, address.getOsSockLen());
        try posix.listen(fd, 128);

        return .{
            .fd = fd,
            .address = address,
        };
    }

    pub fn deinit(self: *TcpListener) void {
        posix.close(self.fd);
    }

    pub fn accept(self: *TcpListener) !TcpConnection {
        var client_addr: std.net.Address = undefined;
        var client_addr_len: posix.socklen_t = @sizeOf(std.net.Address);

        const client_fd = try posix.accept(
            self.fd,
            &client_addr.any,
            &client_addr_len,
            0,
        );

        return .{
            .fd = client_fd,
            .address = client_addr,
        };
    }
};

pub const TcpConnection = struct {
    fd: posix.socket_t,
    address: std.net.Address,

    pub fn connect(addr: [4]u8, port: u16) !TcpConnection {
        const address = std.net.Address.initIp4(addr, port);

        const fd = try posix.socket(
            posix.AF.INET,
            posix.SOCK.STREAM,
            posix.IPPROTO.TCP,
        );
        errdefer posix.close(fd);

        try posix.connect(fd, &address.any, address.getOsSockLen());

        return .{
            .fd = fd,
            .address = address,
        };
    }

    pub fn close(self: *TcpConnection) void {
        posix.close(self.fd);
    }

    pub fn read(self: *TcpConnection, buffer: []u8) !usize {
        return posix.read(self.fd, buffer);
    }

    pub fn readAll(self: *TcpConnection, buffer: []u8) !usize {
        var total: usize = 0;
        while (total < buffer.len) {
            const n = posix.read(self.fd, buffer[total..]) catch |err| {
                if (total > 0) return total;
                return err;
            };
            if (n == 0) break;
            total += n;
        }
        return total;
    }

    pub fn write(self: *TcpConnection, data: []const u8) !usize {
        return posix.write(self.fd, data);
    }

    pub fn writeAll(self: *TcpConnection, data: []const u8) !void {
        var written: usize = 0;
        while (written < data.len) {
            const n = try posix.write(self.fd, data[written..]);
            written += n;
        }
    }
};
