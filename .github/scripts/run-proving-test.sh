#!/usr/bin/env bash
set -euo pipefail

TEST_DIR=proving-stats
OUT_FILE_NAME="$1"

docker compose -f $TEST_DIR/docker-compose.regtest.yml up -d
sleep 5

docker exec bitcoin-regtest bitcoin-cli -regtest -rpcuser=citrea -rpcpassword=citrea loadwallet sequencer
docker exec bitcoin-regtest bitcoin-cli -regtest -rpcuser=citrea -rpcpassword=citrea loadwallet batch-prover

RUST_LOG=off target/debug/citrea --dev --da-layer bitcoin --rollup-config-path $TEST_DIR/configs/sequencer_rollup_config.toml --sequencer $TEST_DIR/configs/sequencer_config.toml --genesis-paths bin/citrea/tests/bitcoin/test-data/gen-proof-input-genesis &
PARALLEL_PROOF_LIMIT=2 target/debug/citrea --dev --da-layer bitcoin --rollup-config-path $TEST_DIR/configs/batch_prover_rollup_config.toml --batch-prover $TEST_DIR/configs/batch_prover_config.toml --genesis-paths bin/citrea/tests/bitcoin/test-data/gen-proof-input-genesis >> batch-prover.log &

mkdir -p $TEST_DIR/results
python3 $TEST_DIR/get-proving-stats.py batch-prover.log $TEST_DIR/results/$OUT_FILE_NAME

pkill citrea
docker compose -f $TEST_DIR/docker-compose.regtest.yml down
# After running the container, change ownership back to the user
sudo chown -R $USER:$USER $TEST_DIR/bitcoin 

# Give some time for the processes to terminate
sleep 2 
# clean the batch prover db for the next run
rm -rf $TEST_DIR/dbs/batch-prover-db
rm batch-prover.log
