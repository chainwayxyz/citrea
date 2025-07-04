# Outline:
- Bitcoin E2E
- Mock E2E
- Etherjs/uniswap/web3_py

- Evm tests:
  - Precomppiles
  - EF tests
  - Call/fork/genesis
  - Queries
  - Sys txs
- STF verifier tests
- Unit tests

## Bitcoin E2E Tests

Bitcoin end-to-end (E2E) tests are the main method for verifying Citrea’s functionality. Using Citrea’s E2E framework, `citrea-e2e`, these tests spawn Citrea nodes, namely sequencer, full node, batch prover, light client prover, that run with Bitcoin Regtest as the DA layer. This setup tests each node’s behaviour and flow, how nodes interact with each other, and how they interact with the Bitcoin network.

### Writing tests with Citrea E2E:

#### Implementing the TestCase Trait
The TestCaseRunner in citrea-e2e expects each test to provide a struct that implements the `TestCase` trait. This trait defines how to configure the test environment and run the test logic. 

#### Configuration methods 
These methods can be overridden to customize the test setup:  

* `test_config`: Returns a `TestCaseConfig` that defines how many Bitcoin nodes and Citrea nodes to spawn, plus options like the genesis directory.

* `test_env`: Returns a `TestCaseEnv` with environment variables for each node process.

* `bitcoin_config`: Returns a `BitcoinConfig` for the Bitcoin Regtest setup (e.g., RPC auth, ports, data directory).

* `scan_l1_start_height`: Optionally sets the starting L1 block height for the full node and the batch prover.

* `throttle_config`: Optionally returns a `ThrottleConfig` to throttle CPU and memory usage for Docker.

* `sequencer_config`, `batch_prover_config`, and `light_client_prover_config` return node-specific configs. Rollup configs of each node are derived from the test_config.  
#### Test flow methods:

* `setup`: Optional method for any custom initialization logic. Runs after nodes are spawned and wallets are funded, but before `run_test` starts.

* `run_test`: **Required** async method with the main test logic. `TestFramework` can be used to send transactions, check state, and verify behaviours.

* `cleanup`: Optional method for cleanup after the test. Runs after nodes shut down.

#### Using TestCaseRunner  
Once a struct that implements the TestCase trait is defined, it can be run with the `TestCaseRunner`. The runner handles setting up the test framework, preparing nodes, funding wallets, connecting services, and executing the test logic.  
To build a `TestCaseRunner`, the test case struct is passed to `TestCaseRunner::new`. Binary paths can be specified using the `set_citrea_path`, `set_citrea_cli_path`, and `set_bitcoin_path` methods. If these are not set, the framework looks(?) to the following environment variables: 
```
CITREA_E2E_TEST_BINARY
CITREA_CLI_E2E_TEST_BINARY
BITCOIN_E2E_TEST_BINARY
CLEMENTINE_E2E_TEST_BINARY 
```  

The `TestCaseRunner::run()` method runs the full test lifecycle: it sets up the framework and nodes, prepares wallets and connections, executes the setup and `run_test` methods, and handles cleanup and log dumping automatically — even if the test panics during execution.

### Scope of Bitcoin E2E tests
Bitcoin end-to-end tests verify critical interactions with the Bitcoin DA layer and the correct flow of each Citrea node. The main areas covered include:

- **Backup and rollback operations**  
  Rollbacks, backup creation, and backup restoration are performed and validated for each node type using citrea-cli.  
- **Bitcoin Service and Verifier**  
  These tests check that the Bitcoin Service processes blocks correctly, extracts relevant blobs, and prepares inclusion and completeness proofs. They also verify that the Verifier validates these proofs accurately against the corresponding Bitcoin block headers.  
- **Fork Activation and Features**  
   Confirms that forks activate at the correct block heights and that features gated behind specific forks remain unavailable until activation, then become accessible as expected.  
- **Full Node Behaviour with L2 Block Syncing and Proofs**  
  Covers how a full node syncs L2 blocks, processes commitments, and verifies proofs in both valid and invalid scenarios, and tracks L2 finality.  
- **Light Client Prover**  
   Verifies the complete light client flow, and tests that the circuit process blocks containing different types of relevant transactions in a correct way.  
- **Bitcoin Transactions**  
  Checks that Bitcoin transactions created by the sequencer and prover nodes are correctly chained. Also assesses behaviour during reorgs, DA monitoring of transactions, and handling of fee bumps.  
- **L2 Transaction Propagation**  
   Confirms that L2 transactions propagate properly between the full node and the sequencer.

## Mock E2E

Mock DA layer: auto block production, 1 blob per block
spawn tasks instead of running seperate processes

- L2 block rule enforcer
- mempool behaviour, tx acceptance and ordering
- all flow, l2 block execution, offchain storage
- RPCs: ledger_getL2, batchProver_prove
- Pruning
- Full node/sequencer/prover restart
- Rollback of different nodes
- Sequencer comm. service/ 
- system txs


## Etherjs/ uniswap/ web3py

Uniswap: deploys erc 20 tokens/ uniswap contracts (factory, pair, router) and performs swap, liquidity adding etc.
Etherjs: Tests integration with the ethers js
web3.py: Tests web3 module's methods

## EVM tests 

- System contract tests (foundry)
- EF tests (evm/src/tests/ef_tests)
- ...

## STF verifier

No DA involved, uses MockZkGuest

- L1 hash related tests( reads and verification)
- Valid/ invalid sequencer commitments, sequential(index, l2 height), previous comm, merkle root. (apply_l2_blocks_from_sequencer_commitments), 
- Prev hash proof
- sequencer pubkey
- L2 block processing: non sequential(height, hash), timestamp, state root

## Light client tests