# Changelog
## [Unreleased]
### Added

### Changed
- refactor: Use reth task manager instead of tokio spawn in sequencer services ([#3145](https://github.com/chainwayxyz/citrea/pull/3145))
- perf: Skip re-execution of proof request in boundless([#3144](https://github.com/chainwayxyz/citrea/pull/3144))
- perf: Mine DA transaction prefix using transaction locktime([#3111](https://github.com/chainwayxyz/citrea/pull/3111))

## [v2.1.0](2026-02-17)
### Added
- Add `linux/arm64` release binary and support for multi-arch (arm64/amd64) docker image. ([#3130](https://github.com/chainwayxyz/citrea/pull/3130))
- feat: implement `eth_sendRawTransactionSync` RPC as per EIP-7966. ([#3095](https://github.com/chainwayxyz/citrea/pull/3095))\
**New env var:**\
  `RPC_MAX_SYNC_SEND_TIMEOUT_MS`: Maximum timeout in milliseconds for `eth_sendRawTransactionSync` (EIP-7966) (default: 20 seconds).

### Changed
- feat: Separate l1 fee rate from block update ([#3131](https://github.com/chainwayxyz/citrea/pull/3131))\
**New env var:**\
  `L1_FEE_RATE_UPDATE_INTERVAL_MS`: L1 fee rate update interval in milliseconds (default: 30 seconds)\
- fix: apply state overrides before `create_txn_env` in `debug_traceCall` ([#3135](https://github.com/chainwayxyz/citrea/issues/3135))

## [v2.0.0] (2026-02-05)
### Changed
- fix: selfdestruct behaviour ([Commit `73aa141`](https://github.com/chainwayxyz/citrea/commit/73aa14186d3e033963b6f396da11900ff33ac9ea))
  See security advisory here: https://github.com/chainwayxyz/citrea/security/advisories/GHSA-356c-q573-6pcq

## [v1.2.2] (2026-01-28)
### Changed
- feat: boundless uses claim digest match ([#3121](https://github.com/chainwayxyz/citrea/pull/3121))

## [v1.2.1] (2026-01-27)
### Added
- docs: Add mainnet run guide at `docs/run-mainnet.md` ([#3119](https://github.com/chainwayxyz/citrea/pull/3119)).

### Changed
- feat: unify fullnode docker image to be usable on mainnet ([#3119](https://github.com/chainwayxyz/citrea/pull/3119)).

## [v1.2.0] (2026-01-07)
### Added
- feat: Initialize metrics at startup. ([#2954](https://github.com/chainwayxyz/citrea/pull/2954))

### Changed
- fix: `bitcoin::network::Testnet` vs `bitcoin::network::Testnet4` confusion in mempool.space fee retrieval ([#3087](https://github.com/chainwayxyz/citrea/pull/3087))
- fix: Limit available RPC methods per node type ([#3088](https://github.com/chainwayxyz/citrea/pull/3088))

## [v1.1.0] (2025-12-17)
### Added
- feat: add with_proof option to `batchProver_getProvingJob` ([#3071](https://github.com/chainwayxyz/citrea/pull/3071))
- feat: Add `batchProver_getLatestProvingSessionInfos` rpc ([#3070](https://github.com/chainwayxyz/citrea/pull/3070))
- feat: Use floating point precision in calculating bitcoin fee rate. ([#3066](https://github.com/chainwayxyz/citrea/pull/3066))

## [v1.0.2] (2025-12-09)
### Added
- perf: Remove validation from backup creation. Backup validation should now be handled by `backup_validate` RPC method. ([#3045](https://github.com/chainwayxyz/citrea/pull/3045))
- feat: Add create backup `citrea-cli` command([#3047](https://github.com/chainwayxyz/citrea/pull/3047))\
  Usage: `citrea-cli create-backup --node-type <NODE_TYPE> --db-path <DB_PATH> --backup-path <BACKUP_PATH>`
- feat: Add `validate-backup` `citrea-cli` command([#3068](https://github.com/chainwayxyz/citrea/pull/3068))\
  Usage: `citrea-cli validate-backup --backup-path <BACKUP_PATH>`
- feat: Store proving session info of LCP ([#3050](https://github.com/chainwayxyz/citrea/pull/3050))\
  `lightClientProver_getLightClientProofByL1Height` endpoint now returns information about the proving session, using the same structure as the batch prover responses.
- ci: Run citrea-e2e tests against bitcoin v30 ([#3054](https://github.com/chainwayxyz/citrea/pull/3054))
- feat: Add `citrea-cli db-migrate` subcommand ([#3015](https://github.com/chainwayxyz/citrea/pull/3015))\
  Usage: `citrea-cli db-migrate --node-type <NODE_TYPE> --db-path <DB_PATH>`

### Changed
- chore: renamed `BOUNDLESS_S3_NO_PRESIGNED` to `BOUNDLESS_S3_USE_PRESIGNED`. ([#3046](https://github.com/chainwayxyz/citrea/pull/3046))\
  **New env var:**\
  `BOUNDLESS_S3_USE_PRESIGNED`: Use presigned URLs for S3 (default: false)\
  New configuration values can also be set inside `batch_prover_config.toml` files under `[risc0_host.prover.Boundless.storage]` with key `s3_use_presigned`.
- fix: multiple tracing related issues fixed. ([#3064](https://github.com/chainwayxyz/citrea/pull/3064))

## [v1.0.1] (2025-12-03)
- chore: Upgrade debian ([#3048](https://github.com/chainwayxyz/citrea/pull/3048))\
  Fixes docker container `chainwayxyz/citrea-full-node`

## [v1.0.0] (2025-12-01)
### Added
- feat(prover): Store proving info by job id ([#3011](https://github.com/chainwayxyz/citrea/pull/3011))\
  `batchProver_getProvingJob*` endpoints now return information about the proving session, including cycle counts and request IDs (bonsai and boundless proofs).
- chore: Add/modify Citrea mainnet values and ZK circuits. ([#3024](https://github.com/chainwayxyz/citrea/pull/3024), [#3025](https://github.com/chainwayxyz/citrea/pull/3025), [#3026](https://github.com/chainwayxyz/citrea/pull/3026), [#3027](https://github.com/chainwayxyz/citrea/pull/3027), [#3028](https://github.com/chainwayxyz/citrea/pull/3028), [#3029](https://github.com/chainwayxyz/citrea/pull/3029), [#3030](https://github.com/chainwayxyz/citrea/pull/3030), [#3031](https://github.com/chainwayxyz/citrea/pull/3031))

## v0.9.0 (2025-11-12)
- feat: Implement eth filter rpc endpoints. ([#2956](https://github.com/chainwayxyz/citrea/pull/2956))\
  &nbsp;&nbsp;**New env vars:**\
  &nbsp;&nbsp;&nbsp;&nbsp; `RPC_STALE_FILTER_TTL` duration in seconds before a stale filter is evicted from active filters cache (default: 300)\
  &nbsp;&nbsp;&nbsp;&nbsp; `RPC_ENABLE_FILTERS` enables or disables the eth filter RPC endpoints (default: true)
  &nbsp;\
  New configuration values can also be set inside `rollup_config.toml` files under `[rpc]` with keys `stale_filter_ttl` or `enable_filters`.

- fix: `eth_estimateGas` and `eth_createAccessList` now supports `state_overrides`. ([#3013](https://github.com/chainwayxyz/citrea/pull/3013))

- feat: Risc0 host configs can now be passed from `prover_config.toml` files. ([#2994](https://github.com/chainwayxyz/citrea/pull/2994))

## v0.8.1 (2025-10-25)
Fixes Testnet guest list for Light Client Prover.

## v0.8.0 (2025-10-24)
Release for Citrea Tangelo network upgrade.

With this upgrade:
- Minimum base fee is reduced to 0.001 Gwei.
- Security fixes from past audits are applied.
- Light Client Proof Batch Proof Method ID updates are now done by the security council.

## v0.7.5 (2025-10-02)
- New config `RPC_ENABLE_JS_TRACER` to enable/disable `JsTracer` for EVM trace RPCs. (Default true).
- Better mempool handling in the sequencer.
- `eth_getBlockByNumber` now supports `pending` block tag.
- Miscellaneous security fixes.

## v0.7.4 (2025-09-08)
Release for improved memory usage in L1 syncing. Node operators on v0.7.3 are highly recommended to upgrade to v0.7.4.

Shutdown pre-v0.7.4 node run below citrea-cli command before running v0.7.4:
```sh
citrea-cli rollback --node-type fullnode --db-path path/to/db --l2-target 9999999999 --l1-target 74247 --sequencer-commitment-index 0
```

## v0.7.3 (2025-08-28)
Release for various bug & vulnerability fixes.

Node operators need to rescan L1:
```sh
citrea-cli rollback --node-type fullnode --db-path path/to/db --l2-target 9999999999 --l1-target 74247 --sequencer-commitment-index 0
```

## v0.7.2 (2025-05-2)
Release for bridge smart contract upgrade and various bug fixes.

Node operators need to rescan L1:

```sh
# use citrea-cli v0.7.2
citrea-cli --rollback --node-type fullnode --db-path path/to/db --l2-target 9999999999 --l1-target 74247 --sequencer-commitment-index 0

citrea-cli clear-pending --db-path path/to/dbs
```


## v0.7.1 (2025-05-2)
Release for risc0 v2.0.2 fix for heap corruption bug.

Node operators need to rescan L1:

```sh
# use citrea-cli v0.7.1
citrea-cli --rollback --node-type fullnode --db-path path/to/db --l2-target 9999999999 --l1-target 74247 --sequencer-commitment-index 0

citrea-cli clear-pending --db-path path/to/dbs
```

## v0.7.0 (2025-04-18)
Release for Citrea Tangerine upgrade. Full nodes needs to be resynced.
- EVM Pectra support (except eip-2935)
- p256r1 precompile.
- Schnorr Verify precompile.
- Rewrite of EVM storage layout, resulting smaller state diffs.
- Rewrite of L2 block and transaction structures.
- Increased block gas limit to 10 million gas.
- Constant sized light client proof.


## v0.6.1 (2025-1-21)
- Fix LedgerDB migration process ([#1730](https://github.com/chainwayxyz/citrea/pull/1730))

## v0.6.0 (2025-1-20)
Citrea Kumquat upgrade will go live on testnet at block 5546000, activating many new features:
- EVM Cancun support.
  - BLOBBASEFEE returns 1 always as blob transactions are not supported.
  - KZG precompile is not activated.
- Offchain smart contracts.
  - Smart contract bytecodes are not committed to the state any more, reducing transaction costs when deploying smart contracts.
- Reduced diff size estimation by accounting for brotli compression discount, resulting in lower transaction costs for all transactions.
- Light client proofs are activated.
  - Succinct ZK proofs for any actor to know Citrea's final state trustlessly by verifying a single ZK proof.

For a detailed list of changes, see auto generated changelog at [v0.6.0 release notes](https://github.com/chainwayxyz/citrea/releases/tag/v0.6.0).

## v0.5.7 (2024-12-21)
- Compatibility version for upcoming v0.6.0

## v0.5.6 (2024-12-13)
- Bitcoin DA finality depth increased to 30 due to long and common testnet4 reorgs. ([commit](https://github.com/chainwayxyz/citrea/commit/cb4a86e8de714fea15698742d77dbafeef82a95a))

## v0.5.5 (2024-12-9)
- 100 wei constant priority fee suggestion from nodes. ([#1561](https://github.com/chainwayxyz/citrea/pull/1561))
- Sequencer checks compressed diff size of a commitment before committing. ([#1349](https://github.com/chainwayxyz/citrea/pull/1349) and [#1557](https://github.com/chainwayxyz/citrea/pull/1557))
- `prover_prove` RPC method now available. ([#1335](https://github.com/chainwayxyz/citrea/pull/1335))
- Prover can now prove locally. ([#1326](https://github.com/chainwayxyz/citrea/pull/1326))
- Prover, sequencer and node configs can now be passed through environment variables. ([#1320](https://github.com/chainwayxyz/citrea/pull/1320))
- Fix Bitcoin DA adapter fee estimation infinite loop bug. ([#1330](https://github.com/chainwayxyz/citrea/pull/1330))

## v0.5.4 (2024-10-11)
- Fixed gas estimation for when a tx has gas limit < block gas limit but with the L1 fee overhead the gas estimation is returned > block gas limit. Preventing transactions from landing on chain. ([#1323](https://github.com/chainwayxyz/citrea/pull/1323))
- Better use of `tokio::spawn_blocking` in Bitcoin DA adapter. ([#1321](https://github.com/chainwayxyz/citrea/pull/1321) [#1324](https://github.com/chainwayxyz/citrea/pull/1324))

## v0.5.3 (2024-10-10)
- `eth_call` RPC now supports state and block overrides. ([#1270](https://github.com/chainwayxyz/citrea/pull/1270))
- `eth_call`, `eth_estimateGas` and `eth_createAccessList` RPCs now supports "pending" block tag. ([#1303](https://github.com/chainwayxyz/citrea/pull/1303))
- Bitcoin DA adapter uses mempool.space API for fee estimation. ([#1302](https://github.com/chainwayxyz/citrea/pull/1302))
- New RPC for prover node: `prover_generateInput`. ([#1280](https://github.com/chainwayxyz/citrea/pull/1280))
- Enhance `eth_estimateGas` RPC L1 fee estimation. ([#1261](https://github.com/chainwayxyz/citrea/pull/1261))
- Structured concurrency and graceful shutdown: fixes breaking storage on shutdown while syncing for the first time. ([#1214](https://github.com/chainwayxyz/citrea/pull/1214) and [#1216](https://github.com/chainwayxyz/citrea/pull/1216))

## v0.5.2 (2024-09-30)
- Added config for disabling prover proving session recovery. ([#1241](https://github.com/chainwayxyz/citrea/pull/1241))
- Nodes now log each RPC request and response. ([#1236](https://github.com/chainwayxyz/citrea/pull/1236))

## v0.5.1 (2024-09-26)

- Fix bug where full nodes would query more l2 blocks than intended. ([#1230](https://github.com/chainwayxyz/citrea/pull/1230))
- Fix bug where full nodes try verifying sequencer commitments which they have not synced up to. ([#1220](https://github.com/chainwayxyz/citrea/pull/1220))
- Set default priority fee to 0. ([#1226](https://github.com/chainwayxyz/citrea/pull/1226))

[unreleased]: https://github.com/chainwayxyz/citrea/compare/v2.1.0...HEAD
[v2.1.0]: https://github.com/chainwayxyz/citrea/compare/v2.0.0...v2.1.0
[v2.0.0]: https://github.com/chainwayxyz/citrea/compare/v1.2.2...v2.0.0
[v1.2.2]: https://github.com/chainwayxyz/citrea/compare/v1.2.1...v1.2.2
[v1.2.1]: https://github.com/chainwayxyz/citrea/compare/v1.2.0...v1.2.1
[v1.2.0]: https://github.com/chainwayxyz/citrea/compare/v1.1.0...v1.2.0
[v1.1.0]: https://github.com/chainwayxyz/citrea/compare/v1.0.2...v1.1.0
[v1.0.2]: https://github.com/chainwayxyz/citrea/compare/v1.0.1...v1.0.2
[v1.0.1]: https://github.com/chainwayxyz/citrea/compare/v1.0.0...v1.0.1
[v1.0.0]: https://github.com/chainwayxyz/citrea/compare/v0.9.0...v1.0.0
