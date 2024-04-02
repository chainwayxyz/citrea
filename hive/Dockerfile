FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
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
FROM rust:latest AS runtime
WORKDIR /app

# Install curl
RUN apt-get update && \
    apt-get install -y curl

# Copying the directory except the target directory
COPY --from=builder /app /app

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/citrea /app/bin/citrea

RUN rm -rf /app/target && cargo

EXPOSE 8545

WORKDIR /app/bin/citrea
ENTRYPOINT ["sh", "-c", "chmod +x ../../hive/hive_publish_block.sh ; ../../hive/hive_publish_block.sh &  ./publish_da_block.sh & ./citrea --genesis-paths ../../hive/genesis --rollup-config-path configs/mock-dockerized/rollup_config.toml --sequencer-config-path configs/mock-dockerized/sequencer_config.toml"]
