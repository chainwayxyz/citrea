# Run a Citrea Mainnet Full Node

This guide covers running a Citrea full node on mainnet.

## Prerequisites

- A fully synced Bitcoin mainnet node (with RPC enabled)
- Docker installed

## Quick Start (Docker)

Run the full node:
```sh
docker run -d \
  -e NETWORK=mainnet \
  -e NODE_URL=<your_bitcoin_url> \
  -e NODE_USERNAME=<your_user> \
  -e NODE_PASSWORD=<your_pass> \
  -v citrea-data:/mnt/task/citrea-db \
  -p 8080:8080 \
  chainwayxyz/citrea-full-node:latest
```

## Environment Variables

**Required:**
| Variable | Description |
|----------|-------------|
| `NETWORK` | Network to run on: `mainnet` |
| `NODE_URL` | Bitcoin node RPC URL |
| `NODE_USERNAME` | Bitcoin RPC username |
| `NODE_PASSWORD` | Bitcoin RPC password |

**Auto-configured per network (can be overridden):**
| Variable | Description |
|----------|-------------|
| `SEQUENCER_PUBLIC_KEY` | Sequencer's public key |
| `SEQUENCER_DA_PUB_KEY` | Sequencer DA public key |
| `PROVER_DA_PUB_KEY` | Prover DA public key |
| `SCAN_L1_START_HEIGHT` | L1 block height to start syncing |
| `SEQUENCER_CLIENT_URL` | Sequencer RPC URL |
