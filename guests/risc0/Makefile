TEST_FEATURES := --features short-prefix

.PHONY: all
all: batch-proof-bitcoin light-client-bitcoin

.PHONY: test
test: batch-proof-bitcoin-test light-client-bitcoin-test

.PHONY: batch-proof-bitcoin
batch-proof-bitcoin:
	cd ../../ && \
	cargo risczero build --manifest-path guests/risc0/batch-proof-bitcoin/Cargo.toml

.PHONY: light-client-bitcoin
light-client-bitcoin:
	cd ../../ && \
	cargo risczero build --manifest-path guests/risc0/light-client-proof-bitcoin/Cargo.toml

.PHONY: batch-proof-bitcoin
batch-proof-bitcoin-test:
	cd ../../ && \
	cargo risczero build $(TEST_FEATURES) --manifest-path guests/risc0/batch-proof-bitcoin/Cargo.toml

.PHONY: light-client-bitcoin
light-client-bitcoin-test:
	cd ../../ && \
	cargo risczero build $(TEST_FEATURES) --manifest-path guests/risc0/light-client-proof-bitcoin/Cargo.toml
