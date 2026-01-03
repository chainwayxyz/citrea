# Citrea CI Golden Image (Debian slim for minimal size with glibc compatibility)
# Contains all dependencies needed for CI workflows
#
# Build: docker build -t citrea-ci:latest -f docker/ci/Dockerfile .
# Test:  docker run --rm -v $(pwd):/workspace -w /workspace citrea-ci:latest make build

ARG PLATFORM=linux/amd64

# ============================================================================
# BUILDER STAGE - Build cargo tools from source
# ============================================================================
FROM --platform=$PLATFORM rust:1.88-slim-bookworm AS cargo-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build all cargo tools in one layer
RUN cargo install --locked dprint --version 0.49.1 && \
    cargo install --locked cargo-nextest --version 0.9.95 && \
    cargo install --locked cargo-llvm-cov --version 0.6.16 && \
    cargo install --locked cargo-udeps --version 0.1.55 && \
    rm -rf /usr/local/cargo/registry /usr/local/cargo/git

# ============================================================================
# FINAL STAGE - Debian slim runtime
# ============================================================================
FROM --platform=$PLATFORM debian:trixie-slim

ENV DEBIAN_FRONTEND=noninteractive

# CI environment variables
ENV CARGO_TERM_COLOR=always
ENV RUSTFLAGS="-D warnings"

# Tool paths - must be explicit for GitHub Actions
ENV RUSTUP_HOME="/usr/local/rustup"
ENV CARGO_HOME="/usr/local/cargo"
ENV RISC0_HOME="/root/.risc0"
ENV PATH="/usr/local/cargo/bin:${RISC0_HOME}/bin:${PATH}"

# ============================================================================
# System Dependencies (minimal set)
# ============================================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential \
    pkg-config \
    libssl-dev \
    clang \
    cmake \
    # Utilities
    curl \
    wget \
    git \
    unzip \
    # SSL/TLS
    ca-certificates \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# Docker CLI (for tests that spawn containers)
# ============================================================================
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
    bookworm stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && apt-get install -y --no-install-recommends docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*

# ============================================================================
# mold linker (fast linking) - download pre-built binary
# ============================================================================
ARG MOLD_VERSION=2.34.1
RUN wget -q https://github.com/rui314/mold/releases/download/v${MOLD_VERSION}/mold-${MOLD_VERSION}-x86_64-linux.tar.gz && \
    tar -xzf mold-${MOLD_VERSION}-x86_64-linux.tar.gz && \
    cp mold-${MOLD_VERSION}-x86_64-linux/bin/mold /usr/local/bin/ && \
    cp mold-${MOLD_VERSION}-x86_64-linux/bin/ld.mold /usr/local/bin/ && \
    rm -rf mold-${MOLD_VERSION}-x86_64-linux*

# ============================================================================
# Protoc (protobuf compiler) - download pre-built binary
# ============================================================================
ARG PROTOC_VERSION=23.2
RUN wget -q https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip && \
    unzip -q protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /usr/local && \
    rm protoc-${PROTOC_VERSION}-linux-x86_64.zip

# ============================================================================
# Rust toolchains (minimal install)
# ============================================================================
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none

# Install required Rust toolchains with minimal components
RUN rustup toolchain install 1.88 --profile minimal --component rustfmt,clippy,llvm-tools-preview,rust-src && \
    rustup toolchain install nightly-2025-09-24 --profile minimal && \
    rustup default 1.88 && \
    rustup target add thumbv6m-none-eabi && \
    rm -rf ${RUSTUP_HOME}/downloads ${RUSTUP_HOME}/tmp

# ============================================================================
# risc0 toolchain
# ============================================================================
ARG RISC0_VERSION=3.0.3
ARG RISC0_RUST_VERSION=1.88.0
RUN curl -L https://risczero.com/install | bash && \
    ${RISC0_HOME}/bin/rzup install cargo-risczero ${RISC0_VERSION} && \
    ${RISC0_HOME}/bin/rzup install cpp && \
    ${RISC0_HOME}/bin/rzup install r0vm ${RISC0_VERSION} && \
    ${RISC0_HOME}/bin/rzup install rust ${RISC0_RUST_VERSION} && \
    ${RISC0_HOME}/bin/rzup default cargo-risczero ${RISC0_VERSION} && \
    ${RISC0_HOME}/bin/rzup default r0vm ${RISC0_VERSION} && \
    ${RISC0_HOME}/bin/rzup default rust ${RISC0_RUST_VERSION} && \
    rm -rf ${RISC0_HOME}/downloads ${RISC0_HOME}/tmp /tmp/*

# ============================================================================
# Copy pre-built cargo tools from builder
# ============================================================================
COPY --from=cargo-builder /usr/local/cargo/bin/dprint /usr/local/cargo/bin/
COPY --from=cargo-builder /usr/local/cargo/bin/cargo-nextest /usr/local/cargo/bin/
COPY --from=cargo-builder /usr/local/cargo/bin/cargo-llvm-cov /usr/local/cargo/bin/
COPY --from=cargo-builder /usr/local/cargo/bin/cargo-udeps /usr/local/cargo/bin/

# ============================================================================
# Configure mold as default linker for Rust
# ============================================================================
RUN mkdir -p /root/.cargo && \
    printf '[target.x86_64-unknown-linux-gnu]\nlinker = "clang"\nrustflags = ["-C", "link-arg=-fuse-ld=/usr/local/bin/mold"]\n' > /root/.cargo/config.toml

# ============================================================================
# Git configuration
# ============================================================================
RUN git config --global --add safe.directory '*'

# ============================================================================
# Ethereum Foundation tests (cached to avoid download during CI)
# ============================================================================
ARG EF_TESTS_URL=https://github.com/ethereum/tests/archive/refs/tags/v16.0.tar.gz
ARG EF_TESTS_DIR=/workspace/crates/evm/ethereum-tests
RUN mkdir -p ${EF_TESTS_DIR} && \
    wget -q ${EF_TESTS_URL} -O /tmp/ethereum-tests.tar.gz && \
    tar -xzf /tmp/ethereum-tests.tar.gz --strip-components=1 -C ${EF_TESTS_DIR} && \
    rm /tmp/ethereum-tests.tar.gz

# ============================================================================
# Cargo directories setup
# ============================================================================
RUN mkdir -p /root/.cargo/git/db \
    /root/.cargo/git/checkouts \
    /root/.cargo/registry \
    && touch /root/.cargo/.package-cache \
    && chmod -R 777 /root/.cargo

# ============================================================================
# Final cleanup
# ============================================================================
RUN rm -rf /tmp/* /var/tmp/* /root/.cache

WORKDIR /workspace
CMD ["/bin/bash"]
