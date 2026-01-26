# Multi-stage Dockerfile for testing Tero Edge Lambda extension with AWS RIE
#
# Uses Alpine Linux throughout to avoid musl/glibc compatibility issues.
# The AWS Lambda RIE works fine on Alpine.

# =============================================================================
# Build Stage - compile the Zig extension in Alpine Linux
# =============================================================================
FROM alpine:edge@sha256:115729ec5cb049ba6359c3ab005ac742012d92bbaa5b8bc1a878f1e8f62c0cb8 AS builder

# Install Zig and build dependencies (same as main Dockerfile)
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

# Fetch dependencies
RUN for i in 1 2 3 4 5; do \
    zig build --fetch && break || \
    (echo "Fetch attempt $i failed, retrying..." && sleep 10); \
    done

# Build the Lambda extension with baseline CPU for ARM64 compatibility
RUN zig build lambda -Dcpu=baseline -Doptimize=ReleaseSafe

# =============================================================================
# Runtime Stage - Alpine with Lambda RIE
# =============================================================================
FROM alpine:3.21@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c

# Install runtime dependencies (same as main Dockerfile) plus bash for bootstrap
RUN apk add --no-cache \
    ca-certificates \
    libstdc++ \
    zlib \
    zstd-libs \
    vectorscan \
    bash \
    curl

# Install the AWS Lambda Runtime Interface Emulator
ADD https://github.com/aws/aws-lambda-runtime-interface-emulator/releases/latest/download/aws-lambda-rie-arm64 /usr/local/bin/aws-lambda-rie
RUN chmod +x /usr/local/bin/aws-lambda-rie

# Create Lambda directory structure
RUN mkdir -p /opt/extensions /var/runtime /var/task

# Copy the extension binary
COPY --from=builder /build/zig-out/bin/edge-lambda /opt/extensions/tero-edge
RUN chmod +x /opt/extensions/tero-edge

# Copy the bootstrap (Lambda function handler)
COPY testing/lambda/bootstrap /var/runtime/bootstrap
RUN chmod +x /var/runtime/bootstrap

# Set environment variables for the extension
ENV TERO_LISTEN_PORT=3000
ENV TERO_UPSTREAM_URL=https://http-intake.logs.datadoghq.com
ENV TERO_LOG_LEVEL=debug

# Lambda environment variables expected by RIE
ENV AWS_LAMBDA_FUNCTION_TIMEOUT=30
ENV AWS_LAMBDA_FUNCTION_NAME=test-function
ENV AWS_LAMBDA_FUNCTION_VERSION=\$LATEST
ENV AWS_LAMBDA_FUNCTION_MEMORY_SIZE=128
ENV AWS_REGION=us-east-1

WORKDIR /var/task

# The RIE will start the extension automatically from /opt/extensions
ENTRYPOINT ["/usr/local/bin/aws-lambda-rie"]
CMD ["/var/runtime/bootstrap"]
