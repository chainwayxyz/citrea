# Auditors Guide for Citrea

## Overview of the Project

Citrea is a ZK rollup that uses Bitcoin as its data availability and settlement layer. 

There is 4 types of nodes that make up the Citrea rollup:
- Sequencer
- Full node
- Batch prover
- Light client prover

See [node-types.md](./node-types.md) for explanation on node types.

Citrea's DA and settlement on Bitcoin is achieved through sequencer commitments and batch proofs. The sequencer commitments are bitcoin transactions that commit to the latest state of the rollup. Batch proofs are Bitcoin transactions that contain Risc0 Groth16 proofs that prove Citrea state goes from A to B when L2 blocks that were committed to by these sequencer commitments are executed. See [sequencer-commitment.md](./sequencer-commitment.md) and [batch-proof-circuit.md](./batch-proof-circuit.md).

These commitments and proofs are read from Bitcoin by full nodes and the light client proof circuit. Full nodes are used by users to access the latest state of the rollup and track the finality of L2 blocks, the light client proof is used by our Bitcoin bridge [Clementine](https://citrea.xyz/clementine_whitepaper.pdf) to resolve disputes (operator challenges). For more detail on full node finality tracking see [finality-tracking.md](./finality-tracking.md); for more detail on the light client proof circuit see [light-client-circuit.md](./light-client-circuit.md). 

## What to look out for

### Obvious
- Loss or freezing of user funds
- Halting the chain (either L2 level or L1 level -- Light Client Proofs)
- Tricking the bridge smart contract with a Bitcoin transaction as if it’s coming from Clementine. (Wrongful cBTC minting)

### Not so obvious
- Split in Light Client Proofs
  - The [Light Client Proof circuit](./light-client-circuit.md) is designed to be deterministic: a Bitcoin block will always yield the same Citrea state upon successful proving. Any behaviour that breaks this assumption can be used to attack Bridge operators.
- Breaking the Batch Proof
  - Any diversion between "native" L2 block execution vs. ["circuit" L2 block execution](./batch-proof-circuit.md)


## Security Assumptions

There is only a single trusted entity in the Citrea rollup, the sequencer, and we trust it for 3 things:

- It won't intentionally send incorrect sequencer commitments that halts the Light Client Proof circuit progression.
- It won't charge unfair L1 fee rates.
- It won't use [system transactions](./eth-mainnet-evm-differences.md#system-transactions) for anything other than [Bitcoin Light Client contract updates](./bitcoin-light-client-contract.md) and [Bridge deposits](./bridge-contract.md).

The batch prover on the other hand is semi-trusted. The batch proof circuit makes sure the prover can't cheat but for now we've decided to have a single prover so batch proofs are signature checked. 


## Crates

- `bin/citrea`: Entrypoint for all Citrea node types.

- `bin/cli`: Utility CLI for Citrea nodes, handles backups, restoring, rollback etc.

- `crates/batch-prover`: Prover node type for the batch proof circuit. (See [batch-proof-circuit.md](./batch-proof-circuit.md) and [node-types.md](./node-types.md#3-batch-prover)).

- `crates/bitcoin-da`: Enables using Bitcoin for Data Availability, both for nodes and ZK circuits, uses taproot commit + reveal scheme like Ordinals protocol to inscribe data.

- `crates/citrea-stf`: Defines the runtime and the main batch proof circuit function. Connects `sov-modules` with the runtime hooks.

- `crates/common`: Utility functions used by nodee-level code.

- `crates/ethereum-rpc`: Fee, syncing, tracing and subscription RPCs for EVM compatibility is defined here.

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

- `guests/risc0`: Batch proof and light client proof circuit targets. These are separated from other crates to allow for more flexible compilation.

You may notice the usage of "node-level" and "circuit-level" code.

**Circuit-level code** refers to code that's also in one of the ZK circuits. This can be code inside the STF or things that happen only in the circuit, such as JMT update proof verification.

**Node-level code** refers to code that's never inside the ZK circuit. This can be RPC related code, or database management.

You will notice throughout the repo "native" feature flag is widely used inside the repo. The purpose of the feature flag is to distinguish between circuit-level and node-level code. For instance, `crates/bitcoin-da/src/service.rs` falls under "native" feature flag of the `bitcoin-da` crate because it defines transaction building and interaction with Bitcoin nodes through RPC APIs, which is not something that can be or will be used inside the ZK circuits.

## Build and Run
If you don't have Rust installed, follow [this link](https://www.rust-lang.org/tools/install) to install Rust on your machine.

Run below command to install prerequisites:

```sh
make install-dev-tools
```

To launch a local Citrea network, please follow [run-dev.md](./run-dev.md). This local network will have `anvil` default addresses funded with `U256::MAX`. Additionally, you can edit `evm.json` file under `resources/genesis/bitcoin-regtest/evm.json` or `resources/genesis/mock/evm.json` to fund any address you want.

To run tests, run below command:

```sh
make test
```


## Known issues
- Non-addressed findings under reports in `audits/`.
- Anything in this [tracking issue](https://github.com/chainwayxyz/citrea/issues/2212).
