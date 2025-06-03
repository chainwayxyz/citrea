# Changelog

## v0.7.1 (2025-05-2)
Release for risc0 v2.0.2 fix for heap corruption bug.

Node operators need to rescan L1:

```sh
# use citrea-cli v0.7.1
citrea-cli --rollback --node-type fullnode --db-path path/to/db --l2-target 9999999999 --l1-target 74247 --sequencer-commitment-index 0

citrea-cli --clear-pending --db-path path/to/dbs 
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
- Enhance `eth_estimateGas` RPC L1 fee estimatation. ([#1261](https://github.com/chainwayxyz/citrea/pull/1261))
- Structured concurrency and graceful shutdown: fixes breaking storage on shutdown while syncing for the first time. ([#1214](https://github.com/chainwayxyz/citrea/pull/1214) and [#1216](https://github.com/chainwayxyz/citrea/pull/1216))

## v0.5.2 (2024-09-30)
- Added config for disableing prover proving session recovery. ([#1241](https://github.com/chainwayxyz/citrea/pull/1241))
- Nodes now log each RPC request and response. ([#1236](https://github.com/chainwayxyz/citrea/pull/1236))

## v0.5.1 (2024-09-26)

- Fix bug where full nodes would query more l2 blocks than intended. ([#1230](https://github.com/chainwayxyz/citrea/pull/1230))
- Fix bug where full nodes try verifying sequencer commitments which they have not synced up to. ([#1220](https://github.com/chainwayxyz/citrea/pull/1220))
- Set default priority fee to 0. ([#1226](https://github.com/chainwayxyz/citrea/pull/1226))