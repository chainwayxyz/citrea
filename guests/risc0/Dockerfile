FROM risczero/risc0-guest-builder:r0.1.81.0 AS build
WORKDIR /src

ARG GUEST_NAME
ARG CITREA_NETWORK

COPY . .

ENV CARGO_MANIFEST_PATH="guests/risc0/${GUEST_NAME}/bitcoin/Cargo.toml"
ENV RUSTFLAGS="-C passes=loweratomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings"
ENV CARGO_TARGET_DIR="target"
ENV CC_riscv32im_risc0_zkvm_elf="/root/.local/share/cargo-risczero/cpp/bin/riscv32-unknown-elf-gcc"
ENV CFLAGS_riscv32im_risc0_zkvm_elf="-march=rv32im -nostdlib"
ENV RISC0_FEATURE_bigint2=""
ENV CITREA_NETWORK=${CITREA_NETWORK}

RUN cargo +risc0 fetch --locked --target riscv32im-risc0-zkvm-elf --manifest-path ${CARGO_MANIFEST_PATH}
RUN cargo +risc0 build --release --locked --target riscv32im-risc0-zkvm-elf --manifest-path ${CARGO_MANIFEST_PATH}

# export stage
FROM scratch AS export

ARG GUEST_NAME

COPY --from=build /src/target/riscv32im-risc0-zkvm-elf/release "/${GUEST_NAME}-bitcoin"
