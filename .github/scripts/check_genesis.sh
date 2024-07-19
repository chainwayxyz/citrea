#!/bin/bash

# Run make command
make genesis

sleep 1

# Check if script generates different genesis
git diff --exit-code

echo "All directories are identical."

exit 0
