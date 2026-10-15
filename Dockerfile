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
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS builder

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

ARG ZIG_VERSION=0.17.0
RUN ARCH="$(uname -m)" && \
    case "$ARCH" in \
    x86_64) ZIG_ARCH="x86_64"; ZIG_SHA256="1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026" ;; \
    aarch64) ZIG_ARCH="aarch64"; ZIG_SHA256="9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8" ;; \
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
RUN zig build ${DISTRIBUTION} -Dcpu=baseline -Doptimize=ReleaseFast \
    -Dversion=${VERSION} -Dcommit=${COMMIT}

# =============================================================================
# Runtime stage - minimal Alpine image
# =============================================================================
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# Upgrade base packages to get security fixes (e.g. openssl) that are newer
# than the pinned image. Install runtime dependencies.
RUN apk upgrade --no-cache \
    && apk add --no-cache \
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

# Bake the distribution's default config to /app/config.json (the CMD arg).
# Every value is overridable at runtime: TERO_-prefixed env vars replace whole
# fields, and ${VAR} references inside the file (e.g. the policy-sync API key)
# are substituted from the environment at load. Distributions without a bundled
# default fall back to env-only config (missing file -> defaults + env).
COPY docker/defaults/ /tmp/defaults/
RUN if [ -f "/tmp/defaults/${DISTRIBUTION}.json" ]; then \
        cp "/tmp/defaults/${DISTRIBUTION}.json" /app/config.json; \
    fi; \
    rm -rf /tmp/defaults

USER tero
EXPOSE 8080

ENTRYPOINT ["/app/edge"]
CMD ["config.json"]
