FROM rust:latest AS runtime
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


ENTRYPOINT ["sh", "-c", "./bin/citrea/publish_da_block.sh & ./target/release/citrea --genesis-paths ./hive/genesis --rollup-config-path ./bin/citrea/configs/mock-dockerized/rollup_config.toml --sequencer-config-path ./bin/citrea/configs/mock-dockerized/sequencer_config.toml"]
