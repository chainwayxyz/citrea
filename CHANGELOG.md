# Changelog

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

- Fix bug where full nodes would query more soft confirmations than intended. ([#1230](https://github.com/chainwayxyz/citrea/pull/1230))
- Fix bug where full nodes try verifying sequencer commitments which they have not synced up to. ([#1220](https://github.com/chainwayxyz/citrea/pull/1220))
- Set default priority fee to 0. ([#1226](https://github.com/chainwayxyz/citrea/pull/1226))