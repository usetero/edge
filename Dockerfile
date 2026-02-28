# Multi-stage Dockerfile for Tero Edge distributions
# Available distributions: edge, datadog, otlp
#
# Examples:
#   docker build --build-arg DISTRIBUTION=edge -t edge .
#   docker build --build-arg DISTRIBUTION=datadog -t edge-datadog .
#   docker build --build-arg DISTRIBUTION=otlp -t edge-otlp .
#
# =============================================================================
# Build stage
# =============================================================================
FROM alpine:edge@sha256:9a341ff2287c54b86425cbee0141114d811ae69d88a36019087be6d896cef241 AS builder

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
    linux-headers \
    pkgconf \
    vectorscan-dev \
    vectorscan-static \
    curl

WORKDIR /build

# Copy source code
COPY build.zig build.zig.zon ./
COPY src/ src/
COPY proto/ proto/

# Build argument for distribution selection
ARG DISTRIBUTION=datadog

RUN for i in 1 2 3 4 5; do \
    zig build --fetch && break || \
    (echo "Fetch attempt $i failed, retrying..." && sleep 10); \
    done

# Build the selected distribution with baseline CPU to ensure cross-ARM64 compatibility
# (GitHub ARM runners use Neoverse-N1, Apple Silicon uses different feature sets)
RUN zig build ${DISTRIBUTION} -Dcpu=baseline -Doptimize=ReleaseSafe

# =============================================================================
# Runtime stage - minimal Alpine image
# =============================================================================
FROM alpine:3.23.3@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

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
