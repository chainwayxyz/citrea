OUT_PATH := resources/guests/risc0/

.PHONY: all
all: batch-proof-bitcoin light-client-bitcoin

.PHONY: batch-proof-bitcoin
batch-proof-bitcoin:
	cd ../../ && \
	cargo risczero build --manifest-path guests/risc0/batch-proof-bitcoin/Cargo.toml

.PHONY: light-client-bitcoin
light-client-bitcoin:
	cd ../../ && \
	cargo risczero build --manifest-path guests/risc0/light-client-proof-bitcoin/Cargo.toml

.PHONY: batch-proof-bitcoin-docker
batch-proof-bitcoin-docker:
	cd ../../ && \
	docker build \
		--platform linux/amd64 \
		--output ./target/riscv-guest/riscv32im-risc0-zkvm-elf/docker \
		-f ./guests/risc0/Dockerfile \
		--build-arg GUEST_NAME=batch-proof-bitcoin \
		--build-arg EXAMPLE_ARG=some-value \
		-t batch-proof-bitcoin:latest \
		--no-cache \
		. && \
	cp ./target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/batch-proof-bitcoin/batch_proof_bitcoin $(OUT_PATH)

.PHONY: light-client-bitcoin-docker
light-client-bitcoin-docker:
	cd ../../ && \
	docker build \
		--platform linux/amd64 \
		--output ./target/riscv-guest/riscv32im-risc0-zkvm-elf/docker \
		-f ./guests/risc0/Dockerfile \
		--build-arg GUEST_NAME=light-client-proof-bitcoin \
		--build-arg EXAMPLE_ARG=some-value \
		-t light-client-proof-bitcoin:latest \
		--no-cache \
		. && \
	cp ./target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/light-client-proof-bitcoin/light_client_proof_bitcoin $(OUT_PATH)
