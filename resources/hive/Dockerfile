FROM rust:1.88 AS runtime
WORKDIR /app


# Install system dependencies
RUN apt-get update && apt-get -y upgrade && \
    apt-get install -y libclang-dev pkg-config && \
    apt-get install protobuf-compiler -y && apt-get install -y curl && \
    apt-get install cmake -y


COPY . .

# Build the project
RUN SKIP_GUEST_BUILD=1 cargo build --release --bin citrea


EXPOSE 8545


ENTRYPOINT ["sh", "-c", "./target/release/citrea --genesis-paths ./resources/genesis/hive --rollup-config-path ./resources/configs/hive/sequencer_rollup_config.toml --sequencer ./resources/configs/hive/sequencer_config.toml"]

