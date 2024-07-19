#!/bin/bash

# Run make command
make genesis

sleep 1

# Check if script generates different genesis
git diff --exit-code ./resources/

if [ $? -ne 0 ]; then
  echo "Differences found in genesis files."
  exit 1
fi

echo "All directories are identical."

exit 0
