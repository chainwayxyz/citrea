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
