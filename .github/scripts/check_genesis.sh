#!/bin/bash

set -euo pipefail

old_wcbtc_code=$(git show HEAD:./resources/genesis/mock/evm.json | jq '.data[] | select(.address == "0x3100000000000000000000000000000000000006") | .code')
old_wcbtc_code_after_hash_removed="${old_wcbtc_code:0:${#old_wcbtc_code}-23}" # Remove characters after hash
old_wcbtc_bytecode_hash="${old_wcbtc_code_after_hash_removed: -64}" # Get last 64 characters (32 bytes hash)
old_wcbtc_before_hash="${old_wcbtc_code_after_hash_removed:0:${#old_wcbtc_code_after_hash_removed}-64}" # Get everything before hash
old_wcbtc_after_hash=${old_wcbtc_code: -23} # Get last 23 characters (after hash)

# Run make command
make genesis

new_wcbtc_code=$(jq '.data[] | select(.address == "0x3100000000000000000000000000000000000006") | .code' ./resources/genesis/mock/evm.json)
new_wcbtc_code_after_hash_removed="${new_wcbtc_code:0:${#new_wcbtc_code}-23}" # Remove characters after hash
new_wcbtc_before_hash="${new_wcbtc_code_after_hash_removed:0:${#new_wcbtc_code_after_hash_removed}-64}" # Get everything before hash
new_wcbtc_after_hash=${new_wcbtc_code: -23} # Get last 23 characters (after hash)

if [ "$old_wcbtc_before_hash" != "$new_wcbtc_before_hash" ] || [ "$old_wcbtc_after_hash" != "$new_wcbtc_after_hash" ]; then
  echo "WCBTC bytecode has changed."
  exit 1
fi

sleep 1

# Check if script generates different genesis, ignoring WCBTC
git diff --exit-code -I $old_wcbtc_before_hash ./resources/

if [ $? -ne 0 ]; then
  echo "Differences found in genesis files."
  exit 1
fi

echo "All directories are identical."

exit 0
