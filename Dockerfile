FROM ubuntu:22.04

RUN apt update && apt -y install curl gcc cpp cmake clang llvm && apt -y autoremove && apt clean && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN /root/.cargo/bin/cargo install cargo-binstall
RUN /root/.cargo/bin/cargo binstall -y cargo-risczero
RUN /root/.cargo/bin/cargo risczero install --version v2024-04-22.0

WORKDIR /citrea
COPY . .

RUN /root/.cargo/bin/cargo build --release
