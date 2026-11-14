# The release tag of https://github.com/ethereum/tests to use for EF tests
EF_TESTS_URL := https://github.com/ethereum/tests/archive/refs/tags/v16.0.tar.gz
EF_TESTS_DIR := crates/evm/ethereum-tests
PARALLEL_PROOF_LIMIT := 1
TEST_FEATURES := --features testing

.PHONY: help
help: ## Display this help message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)


.PHONY: build
build: ## Build the project
	@cargo build

.PHONY: build-reproducible
build-reproducible: ## Build release binaries with reproducible SP1 guests in Docker
	REPR_GUEST_BUILD=1 cargo build --release --locked

build-release: ## Build the project in release mode
	@cargo build --release --locked

clean: ## Cleans compiled
	@cargo clean

clean-node: ## Cleans local dbs needed for sequencer and nodes
	rm -rf resources/dbs/da-db
	rm -rf resources/dbs/sequencer-db
	rm -rf resources/dbs/batch-prover-db
	rm -rf resources/dbs/light-client-prover-db
	rm -rf resources/dbs/full-node-db

clean-txs:
	rm -rf resources/bitcoin/inscription_txs/*

clean-docker:
	rm -rf resources/dbs/citrea-bitcoin-regtest-data

clean-all: clean clean-node clean-txs

test-nocapture: ## Runs test suite with output from tests printed
	PARALLEL_PROOF_LIMIT=1 cargo nextest run --no-capture --retries 0 --workspace --all-features --no-fail-fast $(filter-out $@,$(MAKECMDGOALS))

test: $(EF_TESTS_DIR) ## Runs test suite using nextest
	PARALLEL_PROOF_LIMIT=1 cargo nextest run -j20 --locked --workspace --all-features --no-fail-fast $(filter-out $@,$(MAKECMDGOALS))

.PHONY: test-succinct-network
test-succinct-network: ## Proves on Succinct's prover network and spends PROVE; needs NETWORK_PRIVATE_KEY
	@test -n "$$NETWORK_PRIVATE_KEY" || { echo "Set NETWORK_PRIVATE_KEY to the requester account's key" >&2; exit 1; }
	PARALLEL_PROOF_LIMIT=1 cargo test --locked -p citrea --test bitcoin_e2e --all-features -- succinct_network_test::$(filter-out $@,$(MAKECMDGOALS)) --ignored --test-threads=1 --nocapture

coverage: $(EF_TESTS_DIR) ## Coverage in lcov format
	CITREA_CLI_E2E_TEST_BINARY=$(CURDIR)/target/llvm-cov-target/debug/citrea-cli \
	CITREA_E2E_TEST_BINARY=$(CURDIR)/target/llvm-cov-target/debug/citrea \
	PARALLEL_PROOF_LIMIT=1 \
	cargo llvm-cov --locked --lcov --output-path lcov.info nextest -E 'not test(=pinned_method_ids_match_sp1_hash_u32)' -j20 --workspace --all-features

coverage-html: ## Coverage in HTML format
	cargo llvm-cov --locked --all-features --html nextest --workspace --all-features

install-dev-tools:  ## Installs all necessary cargo helpers
	cargo install --locked dprint --version 0.49.1
	cargo install cargo-llvm-cov --version 0.6.16
	cargo install cargo-hack --version 0.6.36
	cargo install --locked cargo-udeps --version 0.1.55
	cargo install --locked cargo-nextest --version 0.9.95
	$(MAKE) install-sp1
	rustup target add thumbv6m-none-eabi
	rustup component add llvm-tools-preview

install-sp1: ## Install pinned SP1 and compatible guest-build Cargo
	tools/install-sp1up.sh
	"$${SP1_DIR:-$$HOME/.sp1}/bin/sp1up" --version v6.10.0
	tools/verify-sp1-toolchain.sh
	rustup toolchain install 1.96.0 --profile minimal

lint:  ## cargo check and clippy. Skip clippy on guest code since it's not supported by SP1
	## fmt first, because it's the cheapest
	dprint check
	cargo +nightly fmt --all --check
	cargo check --all-targets --all-features
	SKIP_GUEST_BUILD=1 cargo clippy --all-targets --all-features

lint-fix:  ## dprint fmt, cargo fmt, fix and clippy. Skip clippy on guest code since it's not supported by SP1
	dprint fmt
	cargo fix --allow-dirty --all-features
	SKIP_GUEST_BUILD=1 cargo clippy --fix --allow-dirty --all-features
	cargo +nightly fmt --all

check-features: ## Checks that project compiles with all combinations of features.
	cargo hack check --workspace --feature-powerset --exclude-features default --all-targets

find-unused-deps: ## Prints unused dependencies for project. Note: requires nightly
	cargo +nightly udeps --all-targets --all-features

docs:  ## Generates documentation locally
	cargo doc --open

set-git-hook:
	git config core.hooksPath .githooks

# Downloads and unpacks Ethereum Foundation tests in the `$(EF_TESTS_DIR)` directory.
#
# Requires `wget` and `tar`
$(EF_TESTS_DIR):
	mkdir $(EF_TESTS_DIR)
	wget $(EF_TESTS_URL) -O ethereum-tests.tar.gz
	tar -xzf ethereum-tests.tar.gz --strip-components=1 -C $(EF_TESTS_DIR)
	rm ethereum-tests.tar.gz

.PHONY: ef-tests
ef-tests: $(EF_TESTS_DIR) ## Runs Ethereum Foundation tests.
	cargo nextest run -p citrea-evm general_state_tests

%:
	@:

# Basic checks to do before opening a PR
pr:
	$(MAKE) lint
	$(MAKE) test

# Set genesis from system contract source files
genesis:
	$(MAKE) -C crates/evm/src/evm/system_contracts genesis

# Set production genesis from system contract source files
genesis-prod:
	$(MAKE) -C crates/evm/src/evm/system_contracts genesis-prod
