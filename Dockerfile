FROM lukemathwalker/cargo-chef:latest-rust-1.76.0 AS chef
WORKDIR /app

# Builds a cargo-chef plan
FROM chef AS planner
COPY . .
RUN SKIP_GUEST_BUILD=1 cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config && apt-get install protobuf-compiler -y 

# Build dependencies - this is the caching Docker layer!
RUN SKIP_GUEST_BUILD=1 cargo chef cook --release --recipe-path recipe.json

COPY . .
# Build the project
RUN SKIP_GUEST_BUILD=1 cargo build --release --bin citrea

# We need cargo to run the binary because of some path finding dependencies
FROM rust:1.76 AS runtime
WORKDIR /app

# Install curl
RUN apt-get update && \
    apt-get install -y curl

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/citrea /app/examples/demo-rollup/citrea

# Copying the directory except the target directory
COPY --from=builder /app /app
RUN rm -rf /app/target && cargo

EXPOSE 8545

WORKDIR /app/examples/demo-rollup
ENTRYPOINT ["sh", "-c", "./publish_block.sh & ./citrea --genesis-type docker --rollup-config-path mock_dockerized_rollup_config.toml --sequencer-config-path mock_sequencer_config.toml"]
