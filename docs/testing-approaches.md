# Testing in Citrea

Citrea employs a comprehensive testing strategy to ensure correctness and compatibility across all components of the rollup infrastructure. This multi-layered approach includes end-to-end tests with Bitcoin integration, lightweight mock DA tests, EVM compatibility verification, and state transition validation.

## Bitcoin E2E Tests

Bitcoin end-to-end (E2E) tests are the main method for verifying Citrea’s functionality. Using Citrea’s E2E framework, `citrea-e2e`, these tests spawn Citrea nodes, namely sequencer, full node, batch prover, and light client prover, that run with Bitcoin Regtest as the DA layer. This setup tests each node’s behavior and flow, how nodes interact with each other, and how they interact with the Bitcoin network.

### Writing tests with Citrea E2E

#### Implementing the TestCase Trait

The `TestCaseRunner` of `citrea-e2e` expects each test to provide a struct that implements the `TestCase` trait. This trait defines how to configure the test environment and run the test logic. By overriding the trait’s methods, the test setup can be customized, such as configuring which nodes to spawn, setting environment variables for each node, and defining the Bitcoin regtest parameters. Additionally, custom logic for initialization and cleanup steps can be included.

The `run_test` method contains the core test logic and must be implemented. Within this method, the `TestFramework` allows interaction with nodes via RPC endpoints, sending transactions to both the DA layer and L2, triggering commitments and proofs, and performing state assertions.

#### Using TestCaseRunner

Once a struct that implements the `TestCase` trait is defined, it can be run with the `TestCaseRunner`. The runner handles setting up the test framework, preparing nodes, funding wallets, connecting services, and executing the test logic.  

To build a `TestCaseRunner`, the test case struct is passed to `TestCaseRunner::new`. Executable paths can be specified with the following environment variables, or the calling the corresponding functions on top of the runner:

- `CITREA_E2E_TEST_BINARY`  
  Sets the path to the Citrea binary. This can be overridden with `set_citrea_path`.
- `CITREA_CLI_E2E_TEST_BINARY`  
  Sets the path to the Citrea CLI binary. This can be overridden with `set_citrea_cli_path`.

The `TestCaseRunner::run()` method runs the full test lifecycle: it sets up the framework and nodes, prepares wallets and connections, executes the setup and `run_test` methods, and handles cleanup and log dumping automatically — even if the test panics during execution.

#### Execution environment

By default, `citrea-e2e` runs Bitcoin nodes in Docker, and Citrea nodes with the executable. This behaviour can be changed with the boolean environment variables:

- `TEST_BITCOIN_DOCKER`  
  If set to true, runs Bitcoin nodes in Docker using a predefined image. If set to false, runs the `bitcoind` executable from the system.  
    
- `TEST_CITREA_DOCKER`  
  If set to true, runs Citrea nodes in Docker using the image specified by `CITREA_DOCKER_IMAGE` (or a predefined image if not set). If set to false, it runs the Citrea executable from the specified path.

### Scope of Bitcoin E2E tests

Bitcoin end-to-end tests verify critical interactions with the Bitcoin DA layer and the correct flow of each Citrea node. The main areas covered include:

- **Backup and rollback operations**  
  Backup creation and restoration are tested and validated for each node type using `citrea-cli`. Rollback operations are also executed on the full node with `citrea-cli`.  
- **Bitcoin Service and Verifier**  
  These tests check that the Bitcoin Service processes blocks correctly, extracts relevant blobs, and prepares inclusion and completeness proofs. They also verify that the Verifier validates these proofs accurately against the corresponding Bitcoin block headers.  
- **Fork Activation and Features**  
  Confirms that forks activate at the correct block heights and that features gated behind specific forks remain unavailable until activation, then become accessible as expected.  
- **Full Node Behaviour with L2 Block Syncing and Proofs**  
  Covers how a full node syncs L2 blocks, processes commitments, verifies proofs in both valid and invalid scenarios and tracks L2 finality.  
- **Light Client Prover**  
  Verifies the complete light client flow and tests that blocks containing different types of relevant transactions are processed correctly.  
- **Bitcoin Transactions**  
  Checks that Bitcoin transactions created by the sequencer and prover nodes are correctly chained. Also assesses behaviour during reorgs, DA monitoring of transactions, and handling of fee bumps.  
- **L2 Transaction Propagation**  
  Confirms that L2 transactions propagate properly between the full node and the sequencer.

## Mock E2E

Mock end-to-end tests are an alternative to Bitcoin end-to-end tests. They use the Mock DA as the rollup’s DA layer and run tasks with the `TaskExecutor` instead of spawning separate binary processes, making them a quick and lightweight way to write and run tests.

**Note**: When running tests that include Batch Prover nodes, `PARALLEL_PROOF_LIMIT` environment variable must be set.

### Mock DA

The `DaService` and `DaVerifier` traits for the Mock DA are implemented by `MockDaService` and `MockDaVerifier`, respectively. `MockDaService` manages access to mock blobs stored in a database. It supports producing one blob per block and automatically creates a new block whenever a transaction is submitted. It can also simulate reorgs by executing forks, either instantly or at a specified block height.

`MockDaVerifier` acts as the verifier for the Mock DA layer but does not perform real proof verification. Instead, it always accepts inclusion and completeness proofs as valid and directly returns the transactions contained in the completeness proof. For the header chain, it checks that each block header’s height is consecutive with the current DA state and that the `prev_hash` correctly references the latest DA state.

### Scope of Mock E2E tests

The scope of the Mock E2E tests overlaps with the Bitcoin E2E tests. They both verify node behaviours, commitment, and batch-proof flows. Additionally, Mock E2E tests cover:

- **L2 Block Rule Enforcer**  
  Verifies that the sequencer stops block production when the L2 block per L1 block limit is reached, and resumes when there is a new L1 block.  
- **Pruning**  
  Starts the nodes with a set pruning distance, generates L2 blocks, and verifies that the state DB and native DB are pruned by asserting RPC calls fail as expected.  
- **Mempool behaviour**  
  Tests mempool rejection and the order of the valid transactions in the block.  
- **Reopening nodes**  
  Tests for closing and reopening nodes with the same data to ensure the nodes can continue from where they left off.  
- **Rollback Operations**  
  Tests rollback functionality across different node types (full node, sequencer, and batch prover) and validates that full node and batch prover can properly resync after rollback execution.  
- **Sequencer behavior**  
  Verifies sequencer operation, including L2 block production and commitment generation.  
- **System transactions**  
  Tests if system transactions are triggered and they are in the expected L2 blocks.  
- **EVM Tests**  
  Tests Ethereum RPC methods, precompile calls, subscriptions, and tracing endpoints, and verifies L1 diff sizes and gas price changes through test transactions.

## Ethers.js, Uniswap, web3.py Tests

These tests verify Citrea's compatibility with popular Ethereum tooling and protocols by running real-world scenarios. A sequencer and a full node are required to execute these tests.

- **Uniswap**  
  Deploys ERC20 tokens, Uniswap V2 Factory, and Router contracts on Citrea. Creates trading pairs, adds liquidity, performs token swaps, and validates the resulting state changes.  
- **Ethers.js**  
  Tests Ethereum JSON-RPC compatibility using the ethers.js library.  
- **web3.py**  
  Tests Ethereum JSON-RPC compatibility using the web3.py library.

## EVM Tests

EVM tests ensure the correctness and compatibility of Citrea's Ethereum Virtual Machine implementation. These tests cover a wide range of functionalities, including:

- **System Contract Tests**: Validates the behavior of Citrea’s system contracts — including fee vaults, the bridge contract, Bitcoin light client, and WBTC contracts — using Forge tests.  
- **Ethereum Foundation Tests**: Runs a subset of the official Ethereum Foundation test suite, with the test runner located under `crates/evm/src/tests/ef_tests`.  
- **Call, Fork, and Genesis Tests**: Checks contract calls and receipts, fork-specific functionality, and verifies the EVM’s genesis state when initialized with a given configuration.  
- **Query Tests**: Tests Ethereum JSON-RPC methods for retrieving block and transaction data, estimating gas, and filtering events.  
- **System Transactions**: Verifies system transactions, including bridge deposits and withdrawals, and the correct setting of block information in the Bitcoin Light Client.

## State Transition Verifier Tests

Located in the `citrea-stf` crate, these tests focus on the core logic of the batch-proof circuit by verifying the state transitions of sequencer commitments. Most tests call the STF blueprint methods directly to validate their behavior. `MockZkGuest` is used to simulate passing inputs from the host to the guest code.

### Scope

- **Last L1 hash checks**  
  Checks that the last L1 hash can be read and verified correctly from the Bitcoin Light Client contract.  
- **Applying Sequencer Commitments**  
  Tests that sequencer commitments are accepted only if they are sequential in L2 height, properly linked to the previous commitment, and include valid Merkle roots for the L2 block hashes.  
- **L2 block processing**  
  Checks that L2 blocks are validated and applied correctly: block headers must have valid hashes, transaction Merkle roots must match, and sequencer signatures must be verified. The tests also confirm that blocks are applied in order, parent hashes match, timestamps increase as expected, and the limit of L2 blocks per L1 block is enforced.