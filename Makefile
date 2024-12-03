# The release tag of https://github.com/ethereum/tests to use for EF tests
EF_TESTS_URL := https://github.com/chainwayxyz/ef-tests/archive/develop.tar.gz
EF_TESTS_DIR := crates/evm/ethereum-tests
CITREA_E2E_TEST_BINARY := $(CURDIR)/target/debug/citrea
PARALLEL_PROOF_LIMIT := 1

.PHONY: help

help: ## Display this help message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build-risc0
build-risc0:
	$(MAKE) -j 2 -C guests/risc0 all

.PHONY: build-sp1
build-sp1:
	$(MAKE) -C guests/sp1 all

.PHONY: build
build: ## Build the project
	@cargo build

build-release: build-risc0 build-sp1 ## Build the project in release mode
	@cargo build --release

clean: ## Cleans compiled
	@cargo clean

clean-node: ## Cleans local dbs needed for sequencer and nodes
	rm -rf resources/dbs/sequencer-db
	rm -rf resources/dbs/batch-prover-db
	rm -rf resources/dbs/light-client-prover-db
	rm -rf resources/dbs/full-node-db

clean-txs:
	rm -rf resources/bitcoin/inscription_txs/*

clean-docker:
	rm -rf resources/dbs/citrea-bitcoin-regtest-data

clean-all: clean clean-node clean-txs

test-legacy: ## Runs test suite with output from tests printed
	@cargo test -- --nocapture -Zunstable-options --report-time

test: build $(EF_TESTS_DIR) ## Runs test suite using next test
	RISC0_DEV_MODE=1 cargo nextest run --workspace --all-features --no-fail-fast $(filter-out $@,$(MAKECMDGOALS))

install-dev-tools:  ## Installs all necessary cargo helpers
	cargo install --locked dprint
	cargo install cargo-llvm-cov
	cargo install cargo-hack
	cargo install --locked cargo-udeps
	cargo install flaky-finder
	cargo install --locked cargo-nextest
	$(MAKE) install-risc0
	rustup target add thumbv6m-none-eabi
	rustup component add llvm-tools-preview
	$(MAKE) install-sp1

install-risc0:
	cargo install --version 1.7.0 cargo-binstall
	cargo binstall --no-confirm cargo-risczero@1.1.3
	cargo risczero install --version r0.1.81.0

install-sp1: ## Install necessary SP1 toolchain
	curl -L https://sp1.succinct.xyz | bash
	sp1up

lint:  ## cargo check and clippy. Skip clippy on guest code since it's not supported by risc0
	## fmt first, because it's the cheapest
	dprint check
	cargo +nightly fmt --all --check
	cargo check --all-targets --all-features
	$(MAKE) check-fuzz
	SKIP_GUEST_BUILD=1 cargo clippy --all-targets --all-features

lint-fix:  ## dprint fmt, cargo fmt, fix and clippy. Skip clippy on guest code since it's not supported by risc0
	dprint fmt
	cargo +nightly fmt --all
	cargo fix --allow-dirty
	SKIP_GUEST_BUILD=1 cargo clippy --fix --allow-dirty

check-features: ## Checks that project compiles with all combinations of features.
	cargo hack check --workspace --feature-powerset --exclude-features default --all-targets

check-fuzz: ## Checks that fuzz member compiles
	$(MAKE) -C crates/sovereign-sdk/fuzz check

check-no-std: ## Checks that project compiles without std
	$(MAKE) -C crates/sovereign-sdk/rollup-interface $@
	$(MAKE) -C crates/sovereign-sdk/module-system/sov-modules-core $@

find-unused-deps: ## Prints unused dependencies for project. Note: requires nightly
	cargo +nightly udeps --all-targets --all-features

find-flaky-tests:  ## Runs tests over and over to find if there's flaky tests
	flaky-finder -j16 -r320 --continue "cargo test -- --nocapture"

coverage: build $(EF_TESTS_DIR) ## Coverage in lcov format
	cargo llvm-cov --locked --lcov --output-path lcov.info nextest --workspace --all-features

coverage-html: ## Coverage in HTML format
	cargo llvm-cov --locked --all-features --html nextest --workspace --all-features

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
