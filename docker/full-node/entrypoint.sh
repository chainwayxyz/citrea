#!/usr/bin/env bash
set -e

NETWORK="${NETWORK:-mainnet}"
DA_LAYER="${DA_LAYER:-bitcoin}"

echo "=============================================="
echo "Citrea Full Node - ${NETWORK}"
echo "=============================================="

# Resolve genesis path based on network (bundled in image)
GENESIS_PATH="/app/genesis/${NETWORK}"

# Validate genesis path exists
if [ ! -d "$GENESIS_PATH" ]; then
  echo "ERROR: Genesis directory not found at $GENESIS_PATH"
  echo "Available networks: mainnet, testnet, devnet"
  exit 1
fi

# Set network-specific defaults (only if not already provided)
case "$NETWORK" in
  mainnet)
    : "${SEQUENCER_PUBLIC_KEY:=03516a66ea4bc3dab67f94dd356edb4eee00a7b33ffe1ab5a1422de5c7c42df4d6}"
    : "${SEQUENCER_DA_PUB_KEY:=032a31a1fa359abd2e6fc1136b4dea711e5f18618504e021084cc61099f72bb2bd}"
    : "${PROVER_DA_PUB_KEY:=038e501ede61097973e49e714d5f2ad740c82b798bb90fda427fd5138e51f2398e}"
    : "${SCAN_L1_START_HEIGHT:=924022}"
    : "${SEQUENCER_CLIENT_URL:=https://rpc.mainnet.citrea.xyz}"
    ;;
  testnet)
    : "${SEQUENCER_PUBLIC_KEY:=0201edff3b3ee593dbef54e2fbdd421070db55e2de2aebe75f398bd85ac97ed364}"
    : "${SEQUENCER_DA_PUB_KEY:=03015a7c4d2cc1c771198686e2ebef6fe7004f4136d61f6225b061d1bb9b821b9b}"
    : "${PROVER_DA_PUB_KEY:=0357d255ab93638a2d880787ebaadfefdfc9bb51a26b4a37e5d588e04e54c60a42}"
    : "${SCAN_L1_START_HEIGHT:=45496}"
    : "${SEQUENCER_CLIENT_URL:=https://rpc.testnet.citrea.xyz}"
    ;;
  devnet)
    : "${SEQUENCER_PUBLIC_KEY:=03745871636b11562a7f2d7c0e883a960b54c7e2c0a5427d4b99ac403588530589}"
    : "${SEQUENCER_DA_PUB_KEY:=039cd55f9b3dcf306c4d54f66cd7c4b27cc788632cd6fb73d80c99d303c6536486}"
    : "${PROVER_DA_PUB_KEY:=03fc6fb2ef68368009c895d2d4351dcca4109ec2f5f327291a0553570ce769f5e5}"
    : "${SCAN_L1_START_HEIGHT:=0}"
    : "${SEQUENCER_CLIENT_URL:=https://rpc.devnet.citrea.xyz}"
    ;;
  *)
    echo "ERROR: Unknown network '$NETWORK'. Valid options: mainnet, testnet, devnet"
    exit 1
    ;;
esac

# Set defaults for other required config (can be overridden)
: "${STORAGE_PATH:=/mnt/task/citrea-db}"
: "${INCLUDE_TX_BODY:=false}"
: "${SYNC_BLOCKS_COUNT:=10}"
: "${RPC_BIND_HOST:=0.0.0.0}"
: "${RPC_BIND_PORT:=8080}"

# Export for citrea binary
export SEQUENCER_PUBLIC_KEY SEQUENCER_DA_PUB_KEY PROVER_DA_PUB_KEY
export SCAN_L1_START_HEIGHT SEQUENCER_CLIENT_URL
export STORAGE_PATH INCLUDE_TX_BODY SYNC_BLOCKS_COUNT
export RPC_BIND_HOST RPC_BIND_PORT

# Validate required user-provided variables
if [ -z "$NODE_URL" ]; then
  echo "ERROR: NODE_URL environment variable is required"
  echo "Example: -e NODE_URL=http://your-bitcoin-node:8332"
  exit 1
fi

if [ -z "$NODE_USERNAME" ]; then
  echo "ERROR: NODE_USERNAME environment variable is required"
  echo "Example: -e NODE_USERNAME=your_user"
  exit 1
fi

if [ -z "$NODE_PASSWORD" ]; then
  echo "ERROR: NODE_PASSWORD environment variable is required"
  echo "Example: -e NODE_PASSWORD=your_pass"
  exit 1
fi

echo "Configuration:"
echo "  Network:          $NETWORK"
echo "  Genesis path:     $GENESIS_PATH"
echo "  Bitcoin node:     $NODE_URL"
echo "  Sequencer RPC:    $SEQUENCER_CLIENT_URL"
echo "  L1 start height:  $SCAN_L1_START_HEIGHT"
echo "=============================================="

exec ./citrea --da-layer "$DA_LAYER" --genesis-paths "$GENESIS_PATH" --network "$NETWORK"
