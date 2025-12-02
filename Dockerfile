# Multi-stage Dockerfile for Tero Edge distributions
# Build specific distributions with: docker build --build-arg DISTRIBUTION=<name> -t tero-edge-<name> .
# Available distributions: datadog, otlp (future), full
#
# =============================================================================
# Build stage
# =============================================================================
FROM alpine:edge AS builder

# Install Zig and build dependencies from build.zig:
# - zig: compiler
# - zlib-dev/zlib-static: linkSystemLibrary("z")
# - zstd-dev/zstd-static: linkSystemLibrary("zstd")
# - musl-dev: link_libc
# - g++: link_libcpp (C++ for jsoncons)
# - linux-headers: linux/futex.h for libcxx
RUN apk add --no-cache \
    zig="0.15.2-r0" \
    zlib-dev \
    zlib-static \
    zstd-dev \
    zstd-static \
    musl-dev \
    g++ \
    linux-headers

WORKDIR /build

# Copy source code
COPY build.zig build.zig.zon ./
COPY src/ src/
COPY proto/ proto/

# Build argument for distribution selection
ARG DISTRIBUTION=datadog

# Build the selected distribution
RUN zig build ${DISTRIBUTION} -Doptimize=ReleaseSafe

# =============================================================================
# Runtime stage - minimal Alpine image
# =============================================================================
FROM alpine:edge

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libstdc++ \
    zlib \
    zstd-libs \
    && adduser -D -H -s /sbin/nologin tero

WORKDIR /app

# Copy the compiled binary
ARG DISTRIBUTION=datadog
COPY --from=builder /build/zig-out/bin/edge-${DISTRIBUTION} /app/edge

USER tero
EXPOSE 8080

ENTRYPOINT ["/app/edge"]
CMD ["config.json"]
