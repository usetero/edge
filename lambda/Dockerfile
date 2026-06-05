# Lambda Extension Layer Build Dockerfile
#
# Builds the Tero Edge Lambda extension binary for packaging as a Lambda layer.
# Uses Alpine Linux with musl. Since the binary has dynamic dependencies on musl
# libraries, we bundle them in the layer and use a wrapper script.
#
# Build for specific architecture:
#   docker buildx build --platform linux/arm64 -f lambda/Dockerfile -o type=local,dest=.layers .
#   docker buildx build --platform linux/amd64 -f lambda/Dockerfile -o type=local,dest=.layers .

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11

# Install build dependencies from build.zig:
# - zlib-dev/zlib-static: linkSystemLibrary("z")
# - zstd-dev/zstd-static: linkSystemLibrary("zstd")
# - musl-dev: link_libc
# - g++: link_libcpp (C++ for jsoncons)
# - linux-headers: linux/futex.h for libcxx
# - curl/xz: download and unpack the pinned Zig compiler
RUN apk add --no-cache \
    zlib-dev \
    zlib-static \
    zstd-dev \
    zstd-static \
    musl-dev \
    g++ \
    linux-headers \
    pkgconf \
    vectorscan-dev \
    vectorscan-static \
    curl \
    xz

ARG ZIG_VERSION=0.16.0
RUN ARCH="$(uname -m)" && \
    case "$ARCH" in \
    x86_64) ZIG_ARCH="x86_64"; ZIG_SHA256="70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00" ;; \
    aarch64) ZIG_ARCH="aarch64"; ZIG_SHA256="ea4b09bfb22ec6f6c6ceac57ab63efb6b46e17ab08d21f69f3a48b38e1534f17" ;; \
    *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;; \
    esac && \
    curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz && \
    echo "${ZIG_SHA256}  /tmp/zig.tar.xz" | sha256sum -c - && \
    mkdir -p /opt/zig && \
    tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 && \
    ln -s /opt/zig/zig /usr/local/bin/zig && \
    rm /tmp/zig.tar.xz
RUN zig version
WORKDIR /build


# Copy source code
COPY build.zig build.zig.zon ./
COPY src/ src/
COPY proto/ proto/

# Build metadata args
ARG VERSION=dev
ARG COMMIT=unknown

# Fetch dependencies
RUN for i in 1 2 3 4 5; do \
    zig build --fetch && break || \
    (echo "Fetch attempt $i failed, retrying..." && sleep 10); \
    done

# Build the Lambda extension with baseline CPU for broad compatibility
RUN zig build lambda -Dcpu=baseline -Doptimize=ReleaseSafe \
    -Dversion=${VERSION} -Dcommit=${COMMIT}

# Detect architecture for library paths
# IMPORTANT: Only files in /extensions/ are treated as extensions by Lambda.
# The actual binary must be placed elsewhere (in /bin/) to avoid Lambda
# trying to launch it as a separate extension.
RUN ARCH=$(uname -m) && \
    echo "Building for architecture: $ARCH" && \
    mkdir -p /output/extensions /output/lib /output/bin && \
    # Copy the binary to /bin/ (NOT /extensions/ - Lambda would try to launch it)
    cp /build/zig-out/bin/edge-lambda /output/bin/tero-edge-bin && \
    chmod +x /output/bin/tero-edge-bin && \
    # Copy musl dynamic linker and set architecture-specific linker name
    if [ "$ARCH" = "aarch64" ]; then \
    cp /lib/ld-musl-aarch64.so.1 /output/lib/ && \
    MUSL_LINKER="ld-musl-aarch64.so.1"; \
    else \
    cp /lib/ld-musl-x86_64.so.1 /output/lib/ && \
    MUSL_LINKER="ld-musl-x86_64.so.1"; \
    fi && \
    # Copy required shared libraries
    cp /usr/lib/libhs.so.5 /output/lib/ && \
    cp /usr/lib/libz.so.1 /output/lib/ && \
    cp /usr/lib/libzstd.so.1 /output/lib/ && \
    cp /usr/lib/libstdc++.so.6 /output/lib/ && \
    cp /usr/lib/libgcc_s.so.1 /output/lib/ && \
    # Create wrapper script that uses the musl linker directly
    echo '#!/bin/sh' > /output/extensions/tero-edge && \
    echo 'SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"' >> /output/extensions/tero-edge && \
    echo "exec \"\$SCRIPT_DIR/lib/$MUSL_LINKER\" --library-path \"\$SCRIPT_DIR/lib\" \"\$SCRIPT_DIR/bin/tero-edge-bin\" \"\$@\"" >> /output/extensions/tero-edge && \
    chmod +x /output/extensions/tero-edge

# Output stage - copy the layer contents
# Lambda extracts layers to /opt/, so this creates:
#   /opt/extensions/tero-edge  (wrapper script - Lambda launches this)
#   /opt/bin/tero-edge-bin     (actual binary)
#   /opt/lib/*                 (musl libraries)
FROM scratch
COPY --from=0 /output/extensions /extensions
COPY --from=0 /output/bin /bin
COPY --from=0 /output/lib /lib
