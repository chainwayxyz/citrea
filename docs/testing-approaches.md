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
The TestCaseRunner of citrea-e2e expects each test to provide a struct that implements the TestCase trait. This trait defines how to configure the test environment and run the test logic. By overriding the trait’s methods, the test setup can be customized—such as configuring which nodes to spawn, setting environment variables for each node, defining the Bitcoin regtest parameters, and more. Additionally, custom logic for initialization and cleanup steps can be included.

The run_test method contains the core test logic and must be implemented. Within this method, the TestFramework allows you to interact with nodes via RPC endpoints, send transactions to both the DA layer and L2, trigger commitments and proofs, and perform state assertions.

#### Using TestCaseRunner  
Once a struct that implements the TestCase trait is defined, it can be run with the `TestCaseRunner`. The runner handles setting up the test framework, preparing nodes, funding wallets, connecting services, and executing the test logic.  
To build a `TestCaseRunner`, the test case struct is passed to `TestCaseRunner::new`. Binary paths can be specified using the `set_citrea_path`, `set_citrea_cli_path`, and `set_bitcoin_path` methods. If these are not set, the framework searches the binary paths from the environment.

The `TestCaseRunner::run()` method runs the full test lifecycle: it sets up the framework and nodes, prepares wallets and connections, executes the setup and `run_test` methods, and handles cleanup and log dumping automatically — even if the test panics during execution.

### Scope of Bitcoin E2E tests
Bitcoin end-to-end tests verify critical interactions with the Bitcoin DA layer and the correct flow of each Citrea node. The main areas covered include:

- **Backup and rollback operations**  
  Backup creation and restoration are tested and validated for each node type using citrea-cli. Rollback operations are also executed on the full node with citrea-cli.
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

MockE2E tests are an alternative to full end-to-end tests. They use the Mock DA as the rollup’s DA layer and run tasks with the `TaskExecutor` instead of spawning separate binary processes, making them a quick and light-weight way to write and run tests.

### Mock DA

The `DaService` and `DaVerifier` traits for the Mock DA are implemented by `MockDaService` and `MockDaVerifier`, respectively. `MockDaService` manages access to mock blobs stored in a database. It supports producing one blob per block and automatically creates a new block whenever a transaction is submitted. It can also simulate reorgs by executing forks, either instantly or at a specified block height.

`MockDaVerifier` acts as the verifier for the Mock DA layer but does not perform real proof verification. Instead, it always accepts inclusion and completeness proofs as valid and directly returns the transactions contained in the completeness proof. For the header chain, it checks that each block header’s height is consecutive with the current DA state and that the prev_hash correctly references the latest DA state.

### Scope of Mock E2E tests

Scope of the Mock E2E tests overlap with the Bitcoin E2E tests. They both verify node behaviours, commitment and batch proof flows. Additionally Mock E2E tests cover:

- **L2 Block Rule Enforcer**

  Verifies that sequencer stops block production when the L2 block per L1 block limit is reached, and resumes when there is a new L1 block.
- **Pruning**

  Starts the nodes with a set pruning distance, generates L2 blocks, and verifies that the state DB and native DB are pruned by asserting RPC calls fail as expected.
- **Mempool behaviour**

  Tests mempool rejection, and the order of the valid transactions in the block.
- **Reopening nodes**

  Tests for closing down and reopening nodes with the same data to make sure the nodes can continue from where they left off.
- **Rollback Operations**

  Tests rollback functionality across different node types (full node, sequencer, and batch prover) and validates that full node and batch prover can properly resync after rollback execution.
- **Sequencer behaviour**

  Verifies sequencer operation, including L2 block production and commitment generation.
- **System transactions**

  Tests if system transactions are triggered and they are in the expected L2 blocks.

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