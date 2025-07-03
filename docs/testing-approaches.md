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

## Bitcoin E2E

In bitcoin e2e tests, we use bitcoin regtest as the da layer, and test behaviours of different node types, interactions between them, interactions with the Bitcoin network.

- Backups and Rollback(full node) (citrea-cli)
- Bitcoin Service and Verifierw
- Fork activation and features among sequencer/batch prover/fnode
- full node behaviour with L2 block syncing, commitments and proofs (fake vs real)
- Light client flow
- Chaining bitcoin transactions, sequencer and prover
- transaction propagation between fnode and sequencer


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