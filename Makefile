.PHONY: help

help: ## Display this help message
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the the project
	@cargo build

clean: ## Cleans compiled
	@cargo clean

clean-node: ## Cleans local dbs needed for sequencer and nodes
	rm -rf sequencer-db
	rm -rf full-node-db
	rm test-da-dbs/*.db

test-legacy: ## Runs test suite with output from tests printed
	@cargo test -- --nocapture -Zunstable-options --report-time

test:  ## Runs test suite using next test
	@cargo nextest run --workspace --all-features --no-fail-fast -E 'not test(test_instant_finality_data_stored) & not test(test_simple_reorg_case)'


install-dev-tools:  ## Installs all necessary cargo helpers
	cargo install cargo-llvm-cov
	cargo install cargo-hack
	cargo install cargo-udeps
	cargo install flaky-finder
	cargo install cargo-nextest --locked
	cargo install cargo-binstall
	cargo binstall cargo-risczero
	cargo risczero install
	rustup target add thumbv6m-none-eabi

lint:  ## cargo check and clippy. Skip clippy on guest code since it's not supported by risc0
	## fmt first, because it's the cheapest
	cargo +nightly fmt --all --check
	cargo check --all-targets --all-features
	$(MAKE) check-fuzz
	SKIP_GUEST_BUILD=1 cargo clippy --all-targets --all-features

lint-fix:  ## cargo fmt, fix and clippy. Skip clippy on guest code since it's not supported by risc0
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

coverage: ## Coverage in lcov format
	cargo llvm-cov --locked --lcov --output-path lcov.info

coverage-html: ## Coverage in HTML format
	cargo llvm-cov --locked --all-features --html

docs:  ## Generates documentation locally
	cargo doc --open

set-git-hook: 
	git config core.hooksPath .githooks