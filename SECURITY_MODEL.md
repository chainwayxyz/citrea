# Citrea Security Model

This document is for security reviews and scans of this repository. It builds on [docs/auditors-guide.md](docs/auditors-guide.md), and that guide wins wherever the two disagree. For the Clementine bridge, see `THREAT_MODEL.md` in the Clementine repository.

Mainnet is the security target.

## System overview and trust boundaries

Citrea is a ZK rollup that settles on Bitcoin. The sequencer orders L2 blocks and posts sequencer commitments to Bitcoin. The batch prover posts SP1 Groth16 batch proofs to Bitcoin. Full nodes and the light client proof (LCP) circuit read both from Bitcoin. The Clementine bridge uses the `Bridge` system contract to mint and burn cBTC, and uses the LCP to settle disputes.

Trust boundaries:

1. Users reach Citrea only through full node JSON-RPC (`crates/common/src/rpc/server.rs`). Sequencer and batch prover RPCs are not reachable by users on deployment, even though `resources/configs/mainnet/rollup_config.toml` binds to `0.0.0.0`; network exposure is enforced in a non-public infrastructure repository.
2. Bitcoin chain data, which anyone can write, is parsed by the DA layer and the LCP circuit (`crates/bitcoin-da`, `crates/light-client-prover`, `guests/sp1/light-client-proof`).
3. L2 users' EVM transactions are executed by the STF and EVM (`crates/citrea-stf`, `crates/evm`, `guests/sp1/batch-proof`). Native execution and circuit execution must match.

## Components

| Name | Code |
|---|---|
| citrea-stf-evm | `crates/citrea-stf`, `crates/evm` (except `system_contracts`), `crates/l2-block-rule-enforcer`, `crates/sovereign-sdk/module-system`, `crates/sovereign-sdk/rollup-interface`, `crates/primitives`, `guests/sp1/batch-proof` |
| citrea-da-lcp | `crates/bitcoin-da`, `crates/light-client-prover`, `crates/short-header-proof-provider`, `guests/sp1/light-client-proof`, `crates/sovereign-sdk/adapters/mock-da` (off-mainnet) |
| citrea-nodes-rpc | `crates/sequencer`, `crates/fullnode`, `crates/batch-prover`, `crates/ethereum-rpc`, `crates/common`, `crates/storage-ops`, `crates/prover-services`, `crates/sp1`, `crates/sovereign-sdk/full-node`, `crates/sovereign-sdk/adapters/mock-zkvm` (off-mainnet), `bin/`, `docker/`, `devops/`, `resources/configs`, `tools/`, `.github/` |
| bridge-contracts | `crates/evm/src/evm/system_contracts` (Bridge, BitcoinLightClient, fee vaults, WCBTC9) |

## Entry points and who can reach them

- **Sequencer JSON-RPC** (`crates/sequencer/src/rpc.rs`): not reachable by users on deployment; user transactions arrive through full nodes. It registers `eth_sendRawTransaction`, `citrea_sendRawDepositTransaction` and operator methods `citrea_haltCommitments`, `citrea_resumeCommitments`, `citrea_testPublishBlock` and `txpool_removeTransactionsBy*`. Only `backup_*` methods require the API key (`crates/common/src/rpc/auth.rs`), so network isolation is the control for the rest.
- **Batch prover RPC** (`crates/batch-prover/src/rpc.rs`): not reachable by users on deployment. It registers `prove`, `setCommitments`, `submitFakeProof`, `pauseProving` and `retryProvingJob`. The DA fee-bump methods `da_bumpFeeCpfp` and `da_bumpFeeRbf` are registered only on batch provers and sequencers (`bin/citrea/src/rollup/bitcoin.rs`).
- **Full node, LCP and Ethereum RPC** (the only user-facing RPC) (`crates/fullnode/src/rpc.rs`, `crates/light-client-prover/src/rpc.rs`, `crates/ethereum-rpc`): public reads, tracing, `eth_call` and `debug_*`. These are a resource-exhaustion surface, bounded by `gas_cap` in the config.
- **Bitcoin**: anyone can post the inscriptions and transactions that the DA parsers and the LCP circuit consume.

## Assets

- The cBTC supply and the Bridge (`Bridge.sol`). Minting cBTC without a matching Clementine vault is critical.
- The DA wallets of the sequencer and the batch prover (`crates/bitcoin-da/src/utxo_manager.rs`, `tx_signer.rs`).
- The sequencer and batch prover signing keys, `RPC_API_KEY` and `NETWORK_PRIVATE_KEY`.
- Rollup liveness and correctness: L2 chain progress, LCP progress and determinism, and equivalence of native and circuit execution.
- L2 user funds in EVM state and in the fee vaults.

## Attacker profiles

These come from [docs/auditors-guide.md](docs/auditors-guide.md):

- Any L2 user or contract deployer, including through deposit transactions.
- Anyone who writes Bitcoin transactions or inscriptions that the DA layer or the LCP parses.
- Public RPC callers, who reach full nodes only.
- The batch prover is semi-trusted. The circuit is meant to stop it from cheating, and proofs are also signature-checked against a single prover.
- The sequencer is trusted only for three things:
  - it does not send incorrect commitments that halt LCP progress;
  - it does not charge unfair L1 fee rates;
  - it uses system transactions only for light client contract updates and bridge deposits.

  Any other sequencer misbehavior is in scope.

## Existing controls

- Batch proofs are verified by SP1 Groth16 and by the prover's signature.
- The LCP verifies batch proofs and sequencer commitments read from Bitcoin.
- `crates/l2-block-rule-enforcer` applies rules to L2 blocks.
- `backup_*` RPC methods require the API key.
- RPC `gas_cap` bounds call execution.
- Earlier audits are in `audits/`.

## Out of scope and accepted risk

- The sequencer acting against its three trusted duties.
- Findings in `audits/` that have not been addressed, and issues in tracking issue chainwayxyz/citrea#2212.

## Severity

Rate a finding by its demonstrated mainnet impact. That means:

- funds lost or frozen;
- wrongful cBTC minting;
- keys exposed;
- an L2 or LCP chain halt;
- an LCP split;
- divergence between native and circuit execution.

Denial of service and fee waste count only when they cause such a loss or are unbounded. A non-mainnet finding is at most medium; rate it by the same impacts on that network. This is the same rule as Clementine.

Off-mainnet relaxations are intended when mainnet builds or configs disable them: dev mode, mock DA, test-only RPCs (`citrea_testPublishBlock`, `submitFakeProof`), example keys and small regtest parameters.

## Rating findings against this model

These rules apply the sections above to individual findings:

- A finding that needs a user to reach sequencer or batch prover RPC, or other operator-only access, is defense in depth. Rate it low.
- A finding that needs the sequencer to break one of its three trusted duties is out of scope, unless another attacker can trigger it.
- A finding already in `audits/` and not addressed, or in chainwayxyz/citrea#2212, is a known issue.
- A finding reachable only through dev mode, mock DA, mock zkVM, test-only RPCs, example keys or regtest parameters that mainnet disables is informational.
- A finding that affects only testnet or devnet deployments (`resources/configs/testnet`, `resources/configs/devnet`) is at most medium, per the severity rule above.
- A finding in third-party dependency code itself, including `crates/evm/src/evm/system_contracts/lib` (except `WitnessUtils.sol`), is low. Misuse and pinning of dependencies are rated by their impact.
- Wrongful cBTC minting through a confirmed path is critical.

## Finding tags

Security scans tag each finding with:

- `Component`: the component from the table above.
- `CVE`: the CVE ID, for findings about a vulnerable dependency.
- `network`: where the impact is real: `mainnet`, `testnet` or `regtest`.
- `code-level`: `circuit` if the affected code runs inside an SP1 guest or the proven state transition, `node-only` if it runs only natively in a node.

## Open questions

- Network exposure of sequencer, batch prover and LCP RPCs is enforced in the non-public infrastructure repository. Security scans cannot verify it, so they rely on the statement above.
