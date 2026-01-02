# Citrea CI Golden Image
# Contains all dependencies needed for CI workflows
#
# Build: docker build -t citrea-ci:latest -f docker/ci/Dockerfile .
# Test:  docker run --rm -v $(pwd):/workspace -w /workspace citrea-ci:latest make build

ARG PLATFORM=linux/amd64
FROM --platform=$PLATFORM ubuntu:24.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# ============================================================================
# CRITICAL: Set explicit paths for all tools
# GitHub Actions overrides HOME, RUSTUP_HOME, CARGO_HOME when running containers.
# We must set these explicitly to where we install the tools during docker build.
# ============================================================================
ENV RUSTUP_HOME="/root/.rustup"
ENV CARGO_HOME="/root/.cargo"
ENV RISC0_HOME="/root/.risc0"

# CI environment variables
ENV CARGO_TERM_COLOR=always
ENV RUSTFLAGS="-D warnings"

# Add tool paths (use explicit paths, not $HOME-relative)
ENV PATH="/root/.cargo/bin:/root/.rustup/bin:/root/.risc0/bin:/root/.local/bin:/usr/local/bin:${PATH}"

# ============================================================================
# System Dependencies
# ============================================================================
RUN apt-get update && apt-get install -y \
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
    lsb-release \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# Docker CLI (for tests that spawn containers)
# ============================================================================
RUN install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    chmod a+r /etc/apt/keyrings/docker.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && apt-get install -y docker-ce-cli && \
    rm -rf /var/lib/apt/lists/*

# ============================================================================
# mold linker (fast linking)
# ============================================================================
ARG MOLD_VERSION=2.34.1
RUN wget -q https://github.com/rui314/mold/releases/download/v${MOLD_VERSION}/mold-${MOLD_VERSION}-x86_64-linux.tar.gz && \
    tar -xzf mold-${MOLD_VERSION}-x86_64-linux.tar.gz && \
    cp mold-${MOLD_VERSION}-x86_64-linux/bin/mold /usr/local/bin/ && \
    cp mold-${MOLD_VERSION}-x86_64-linux/bin/ld.mold /usr/local/bin/ && \
    rm -rf mold-${MOLD_VERSION}-x86_64-linux*

# ============================================================================
# Protoc (protobuf compiler)
# ============================================================================
ARG PROTOC_VERSION=23.2
RUN wget -q https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip && \
    unzip -q protoc-${PROTOC_VERSION}-linux-x86_64.zip -d /usr/local && \
    rm protoc-${PROTOC_VERSION}-linux-x86_64.zip

# ============================================================================
# Rust toolchains
# ============================================================================
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none

# Install required Rust toolchains:
# - 1.88: Primary toolchain (must match rust-toolchain.toml exactly)
# - nightly: For formatting and some features
# - nightly-2025-09-24: For udeps (pinned version)
RUN rustup toolchain install 1.88 --profile minimal --component rustfmt,clippy,llvm-tools-preview,rust-src && \
    rustup toolchain install nightly --profile minimal --component rustfmt,clippy,llvm-tools-preview && \
    rustup toolchain install nightly-2025-09-24 --profile minimal && \
    rustup default 1.88 && \
    rustup target add thumbv6m-none-eabi

# ============================================================================
# risc0 toolchain
# ============================================================================
ARG RISC0_VERSION=3.0.3
ARG RISC0_RUST_VERSION=1.88.0
RUN curl -L https://risczero.com/install | bash && \
    /root/.risc0/bin/rzup install cargo-risczero ${RISC0_VERSION} && \
    /root/.risc0/bin/rzup install cpp && \
    /root/.risc0/bin/rzup install r0vm ${RISC0_VERSION} && \
    /root/.risc0/bin/rzup install rust ${RISC0_RUST_VERSION} && \
    /root/.risc0/bin/rzup default cargo-risczero ${RISC0_VERSION} && \
    /root/.risc0/bin/rzup default r0vm ${RISC0_VERSION} && \
    /root/.risc0/bin/rzup default rust ${RISC0_RUST_VERSION}

# ============================================================================
# Cargo tools
# ============================================================================
# dprint - TOML/code formatting
RUN cargo install --locked dprint --version 0.49.1

# cargo-nextest - Fast test runner
RUN cargo install --locked cargo-nextest --version 0.9.95

# cargo-llvm-cov - Code coverage
RUN cargo install --locked cargo-llvm-cov --version 0.6.16

# cargo-udeps - Unused dependencies checker
RUN cargo install --locked cargo-udeps --version 0.1.55

# ============================================================================
# Configure mold as default linker for Rust
# ============================================================================
RUN mkdir -p /root/.cargo && \
    echo '[target.x86_64-unknown-linux-gnu]\nlinker = "clang"\nrustflags = ["-C", "link-arg=-fuse-ld=/usr/local/bin/mold"]' > /root/.cargo/config.toml

# ============================================================================
# Git configuration
# GitHub Actions mounts the workspace with different ownership than the container user.
# This prevents "dubious ownership" errors.
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

RUN mkdir -p \
    /root/.cargo/git/db \
    /root/.cargo/git/checkouts \
    /root/.cargo/registry

# ============================================================================
# Workspace setup
# ============================================================================
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]

