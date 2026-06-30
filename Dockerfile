# Multi-stage Dockerfile for Tero Edge distributions
# Available distributions: edge, datadog, otlp, prometheus, tail
#
# Examples:
#   docker build --build-arg DISTRIBUTION=edge -t edge .
#   docker build --build-arg DISTRIBUTION=datadog -t edge-datadog .
#   docker build --build-arg DISTRIBUTION=otlp -t edge-otlp .
#   docker build --build-arg DISTRIBUTION=prometheus -t edge-prometheus .
#   docker build --build-arg DISTRIBUTION=tail -t edge-tail .
#
# =============================================================================
# Build stage
# =============================================================================
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS builder

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

# Build argument for distribution selection
ARG DISTRIBUTION=datadog
ARG VERSION=dev
ARG COMMIT=unknown

RUN for i in 1 2 3 4 5; do \
    zig build --fetch && break || \
    (echo "Fetch attempt $i failed, retrying..." && sleep 10); \
    done

# Build the selected distribution with baseline CPU to ensure cross-ARM64 compatibility
# (GitHub ARM runners use Neoverse-N1, Apple Silicon uses different feature sets)
RUN zig build ${DISTRIBUTION} -Dcpu=baseline -Doptimize=ReleaseSafe \
    -Dversion=${VERSION} -Dcommit=${COMMIT}

# =============================================================================
# Runtime stage - minimal Alpine image
# =============================================================================
FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libstdc++ \
    zlib \
    zstd-libs \
    vectorscan \
    && adduser -D -H -s /sbin/nologin tero

WORKDIR /app

# Copy the compiled binary
ARG DISTRIBUTION=datadog
COPY --from=builder /build/zig-out/bin/edge-${DISTRIBUTION} /app/edge

USER tero
EXPOSE 8080

ENTRYPOINT ["/app/edge"]
CMD ["config.json"]
