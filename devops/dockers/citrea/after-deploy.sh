#!/bin/bash

SERVICE="$1"
SCRIPT_DIR="$(temp=$( realpath "$0"  ) && dirname "$temp")"

echo "Starting after-deploy cleanup..."

# docker images
echo "Removing all Docker images containing '$SERVICE'..."
docker images --format '{{.Repository}}:{{.Tag}}' | grep "$SERVICE" | xargs -r docker rmi -f || true

# Safety check before using rm -rf
if [[ -z "$SCRIPT_DIR" ]]; then
  echo "$SCRIPT_DIR is empty! Aborting to prevent accidental deletion."
  exit 66 # EX_NOINPUT — missing directory or file
fi

# Downloaded and generated files
echo "Deleting downloaded binaries, generated files, and copied folders..."
rm -f "$SCRIPT_DIR/dockers/citrea/citrea" || true
rm -f "$SCRIPT_DIR/dockers/citrea/citrea-cli" || true
rm -f "$SCRIPT_DIR/dockers/citrea/r0vm" || true
rm -f "$SCRIPT_DIR/dockers/citrea/.build-args" || true
rm -rf "$SCRIPT_DIR/dockers/citrea/genesis" || true

echo "after-deploy cleanup done."