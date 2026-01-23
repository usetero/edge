# Lambda Extension Build Dockerfile
#
# Builds the Tero Edge Lambda extension binary for packaging as a Lambda layer.
# Uses Alpine Linux for musl-based static linking.
#
# Build for specific architecture:
#   docker buildx build --platform linux/arm64 -f Lambda.Dockerfile -o type=local,dest=.layers .
#   docker buildx build --platform linux/amd64 -f Lambda.Dockerfile -o type=local,dest=.layers .

FROM alpine:edge@sha256:115729ec5cb049ba6359c3ab005ac742012d92bbaa5b8bc1a878f1e8f62c0cb8

# Install Zig and build dependencies
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
    vectorscan-static

WORKDIR /build

# Copy source code
COPY build.zig build.zig.zon ./
COPY src/ src/
COPY proto/ proto/

# Fetch dependencies
RUN for i in 1 2 3 4 5; do \
    zig build --fetch && break || \
    (echo "Fetch attempt $i failed, retrying..." && sleep 10); \
    done

# Build the Lambda extension with baseline CPU for broad compatibility
RUN zig build lambda -Dcpu=baseline -Doptimize=ReleaseSafe

# Create the Lambda layer structure
# Extensions must be in /opt/extensions/ when deployed
RUN mkdir -p /output/extensions && \
    cp /build/zig-out/bin/edge-lambda /output/extensions/tero-edge && \
    chmod +x /output/extensions/tero-edge

# Output stage - copy just the layer contents
FROM scratch
COPY --from=0 /output/extensions /extensions
