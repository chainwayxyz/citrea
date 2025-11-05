#!/bin/bash

# Usage: ./pre-build.sh <service_name> <release> <network> <platform>
# Example: ./pre-build.sh full-node v0.8.1 dev-net linux-amd64

set -euo pipefail

SERVICE="$1"
RELEASE="$2"
NETWORK="$3"
PLATFORM="$4"
SCRIPT_DIR="$(temp=$( realpath "$0"  ) && dirname "$temp")"
REPO="chainwayxyz/citrea"
R0VM_URL="https://static.citrea.xyz/$NETWORK/resources/r0vm"
DA_LAYER="${DA_LAYER:-bitcoin}"
GENESIS_PATH="${GENESIS_PATH:-genesis}"

cd "$SCRIPT_DIR"

## Check and Download binaries
download_binary() {
  BINARY_NAME="$1"
  BINARY_URL="https://github.com/${REPO}/releases/download/${RELEASE}/${BINARY_NAME}-${RELEASE}-${PLATFORM}"

  echo "Downloading ${BINARY_NAME} from ${BINARY_URL}"
  wget -O "$BINARY_NAME" "$BINARY_URL"
  chmod +x "$BINARY_NAME"
}

download_binary "citrea"
download_binary "citrea-cli"

## Copy r0vm binary
wget -O r0vm "$R0VM_URL"

## Copy genesis folder
FORMATTED_NETWORK="${NETWORK//-/}"
cp -r "$SCRIPT_DIR"/../../../resources/genesis/"$FORMATTED_NETWORK" ./genesis

## Create .build-args file in .env format
cat > "./.build-args" <<EOF
DA_LAYER=$DA_LAYER
GENESIS_PATH=$GENESIS_PATH
NETWORK=$NETWORK
SERVICE_TYPE=$SERVICE
EOF

chmod +x entrypoint.sh r0vm
