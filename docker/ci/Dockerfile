# Citrea CI Golden Image
# Contains all dependencies needed for CI workflows
#
# Build: docker build -t citrea-ci:latest -f docker/ci/Dockerfile .
# Test:  docker run --rm -v $(pwd):/workspace -w /workspace citrea-ci:latest make build

ARG PLATFORM=linux/amd64
FROM --platform=$PLATFORM ubuntu:24.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# CI environment variables
ENV CARGO_TERM_COLOR=always
ENV RUSTFLAGS="-D warnings"
ENV FOUNDRY_PROFILE=ci

# Add tool paths
ENV PATH="/root/.cargo/bin:/root/.risc0/bin:/root/.foundry/bin:/root/.local/bin:${PATH}"

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
    jq \
    unzip \
    # Python
    python3 \
    python3-pip \
    python3-venv \
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
# Node.js 18.x (for uniswap/ethers tests)
# ============================================================================
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/*

# ============================================================================
# Rust toolchains
# ============================================================================
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none

# Install required Rust toolchains:
# - 1.88.0: Primary toolchain (from rust-toolchain.toml)
# - nightly: For formatting and some features
# - nightly-2025-09-24: For udeps (pinned version)
RUN rustup toolchain install 1.88.0 --profile minimal --component rustfmt,clippy,llvm-tools-preview,rust-src && \
    rustup toolchain install nightly --profile minimal --component rustfmt,clippy,llvm-tools-preview && \
    rustup toolchain install nightly-2025-09-24 --profile minimal && \
    rustup default 1.88.0 && \
    rustup target add thumbv6m-none-eabi

# ============================================================================
# risc0 toolchain
# ============================================================================
ARG RISC0_VERSION=3.0.3
RUN curl -L https://risczero.com/install | bash && \
    /root/.risc0/bin/rzup install cargo-risczero ${RISC0_VERSION} && \
    /root/.risc0/bin/rzup install cpp && \
    /root/.risc0/bin/rzup install r0vm ${RISC0_VERSION} && \
    /root/.risc0/bin/rzup install rust 1.88.0 && \
    /root/.risc0/bin/rzup default cargo-risczero ${RISC0_VERSION} && \
    /root/.risc0/bin/rzup default r0vm ${RISC0_VERSION} && \
    /root/.risc0/bin/rzup default rust 1.88.0 && \
    # Link risc0 rust toolchain to rustup so risc0-build can find it
    rustup toolchain link risc0 /root/.risc0/toolchains/rust-1.88.0

# ============================================================================
# Foundry (Solidity development)
# ============================================================================
ARG FOUNDRY_VERSION=v1.3.6
RUN curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup --version ${FOUNDRY_VERSION}

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

# cargo-hack - Feature flag testing
RUN cargo install --locked cargo-hack --version 0.6.36

# ============================================================================
# Python tools
# ============================================================================
RUN pip3 install --break-system-packages codespell

# ============================================================================
# Configure mold as default linker for Rust
# ============================================================================
RUN mkdir -p /root/.cargo && \
    echo '[target.x86_64-unknown-linux-gnu]\nlinker = "clang"\nrustflags = ["-C", "link-arg=-fuse-ld=/usr/local/bin/mold"]' > /root/.cargo/config.toml

# ============================================================================
# Workspace setup
# ============================================================================
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]

