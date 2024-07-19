#!/bin/bash

# Paths
paths=( "./resources/genesis/bitcoin-regtest/evm.json" 
        "./resources/genesis/mock/evm.json" 
        "./resources/genesis/mock-dockerized/evm.json" 
        "./resources/test-data/demo-tests/bitcoin-regtest/evm.json" 
        "./resources/test-data/demo-tests/mock/evm.json" 
        "./resources/test-data/integration-tests/evm.json" 
        "./resources/test-data/integration-tests-low-block-gas-limit/evm.json" 
        "./resources/test-data/integration-tests-low-max-l2-blocks-per-l1/evm.json")

# Function to clean up copied directories
cleanup() {
    for path in "${paths[@]}"; 
    do
        rm -rf "${path}_tmp"
    done
}
cleanup

sleep 1

# Copy directories
for path in "${paths[@]}"; 
do
    cp -r "$path" "${path}_tmp"
done

sleep 1

# Run make command
make genesis

# Compare directories
for path in "${paths[@]}"; 
do
    diff -r "$path" "${path}_tmp"
    if [ $? -ne 0 ]; then
        echo "Error: Differences found between $path and ${path}_tmp"
        cleanup
        exit 1
    fi
done

echo "All directories are identical."
sleep 1

# Clean up copied directories
cleanup

exit 0
