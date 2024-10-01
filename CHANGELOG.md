# Changelog

## v0.5.2 (2024-09-30)
- Added config for disableing prover proving session recovery. ([#1241](https://github.com/chainwayxyz/citrea/pull/1241))
- Nodes now log each RPC request and response. ([#1236](https://github.com/chainwayxyz/citrea/pull/1236))

## v0.5.1 (2024-09-26)

- Fix bug where full nodes would query more soft confirmations than intended. ([#1230](https://github.com/chainwayxyz/citrea/pull/1230))
- Fix bug where full nodes try verifying sequencer commitments which they have not synced up to. ([#1220](https://github.com/chainwayxyz/citrea/pull/1220))
- Set default priority fee to 0. ([#1226](https://github.com/chainwayxyz/citrea/pull/1226))