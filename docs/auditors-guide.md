# Auditors Guide for Citrea

## Overview of the Project

What it is:

Core components: sequencer, full node, batch prover, light client prover

Diagram(s)
- Transaction submission and inclusion
- blocks & commitments & batch proofs & lcp
- 

## Crates

- `bin/citrea`: Entrypoint for all Citrea node types.

- `bin/cli`: Utility CLI for Citrea nodes, handles backups, restoring, rollback etc.

- `crates/batch-prover`: Prover node type for the batch proof circuit. (See [batch-proof-circuit.md](./batch-proof-circuit.md) and [node-types.md](./node-types.md#3-batch-prover)).

- `crates/bitcoin-da`: Enables using Bitcoin for Data Availavbility, both for nodes and ZK circuits.

- `crates/citrea-stf`: Defines the runtime and the main batch proof circuit function. Connects `sov-modules` with the runtime hooks.

- `crates/common`: Utility functions used by nodee-level code.

- `crates/ethereum-rpc`: Fee, syncing, tracing and subscription RPCs for EVM compatability is defined here.

- `crates/evm`: Citrea's EVM implementation.
    - System contracts under `crates/evm/src/evm/system_contracts`.

- `crates/fullnode`: Citrea full node implementation. (See [](./node-types.md#2-full-node)).

- `crates/l2-block-rule-enforcer`: `sov-module` that applies certain rules on L2 blocks. 

- `crates/light-client-prover`: Prover node type for the light client proof circuit. (See [light-client-proof-circuit.md](./light-client-circuit.md) and [node-types.md](./node-types.md#4-light-client-prover)).

- `crates/primitives`: Utility funcctions used by node-leve and circuit-level code.

- `crates/prover-services`: Enables parallelizing ZK proof production.

- `crates/risc0`: Risc0 ZK Vm adapter.

- `crates/sequencer`: Citrea sequencer implementation. (See [node-types.md](./node-types.md#1-sequencer-node)).

- `crates/short-header-proof-provider`:

- `crates/sovereign-sdk`: Forked version of [sovereign-sdk](https://github.com/Sovereign-Labs/sovereign-sdk).

- `crates/storage-ops`: Database operations like pruning and rollback.

- `guests/risc0`: Batch proof and light client proof circuit targets. These are seperated from other crates to allow for more flexible compilation.

You may notice the usage of "node-level" and "circuit-level" code.

**Circuit-level code** refers to code that's also in one of the ZK circuits. This can be code inside the STF or things that happen only in the circuit, such as JMT update proof verification.

**Node-level code** refers to code that's never inside the ZK circuit. This can be RPC related code, or database management.

You will notice throughout the repo "native" feature flag is widely used. The purpose of the fetaure flag is to distinguish between circuit-level and node-level code. For instance, `crates/bitcoin-da/src/service.rs` falls under "native" feature flag of the `bitcoin-da` crate because it defines transaction building and interaction with Bitcoin nodes through RPC APIs, which is not something that can be or will be used inside the ZK circuits.

## Build and Run
If you don't have Rust installed, follow [this link](https://www.rust-lang.org/tools/install) to install Rust on your machine.

Run below command to install prerequisites:

```sh
make install-dev-tools
```

To launch a local Citrea network, please follow [run-dev.md](./run-dev.md)

To run tests, run below command:

```sh
make test
```

## Security Assumptions
