ifndef CITREA_NETWORK
$(error CITREA_NETWORK is not set)
endif

OUT_PATH := resources/guests/risc0/

.PHONY: batch-proof-bitcoin-docker
batch-proof-bitcoin-docker:
	cd ../../ && \
	docker build \
		--platform linux/amd64 \
		--output ./target/riscv-guest/riscv32im-risc0-zkvm-elf/docker \
		-f ./guests/risc0/Dockerfile \
		--build-arg GUEST_NAME=batch-proof \
		--build-arg CITREA_NETWORK=$(CITREA_NETWORK) \
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
		--build-arg GUEST_NAME=light-client-proof \
		--build-arg CITREA_NETWORK=$(CITREA_NETWORK) \
		-t light-client-proof-bitcoin:latest \
		--no-cache \
		. && \
	cp ./target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/light-client-proof-bitcoin/light_client_proof_bitcoin $(OUT_PATH)
