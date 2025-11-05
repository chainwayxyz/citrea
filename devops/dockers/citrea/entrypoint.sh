#!/bin/bash
set -e

START_WAIT="${START_WAIT:-5}"
STOP_WAIT="${STOP_WAIT:-5}"
SHUTDOWN_COMMAND=""
MAIN_PROCESS_PID=""

# Citrea default arguments
DA_LAYER="${DA_LAYER:-bitcoin}"
GENESIS_PATH="${GENESIS_PATH:-genesis}"

shutdown_gracefully() {
    echo "Shutting down container..."
    if [ -n "$SHUTDOWN_COMMAND" ]; then
        echo "Running: $SHUTDOWN_COMMAND"
        if eval "$SHUTDOWN_COMMAND"; then
            echo "Shutdown command ran successfully."
        else
            echo "Shutdown command failed."
        fi
    elif [ -n "$MAIN_PROCESS_PID" ] && kill -0 "$MAIN_PROCESS_PID" 2>/dev/null; then
        echo "Sending SIGINT to main process (PID $MAIN_PROCESS_PID)"
        kill -SIGINT "$MAIN_PROCESS_PID"
        wait "$MAIN_PROCESS_PID"
    fi
    sleep "$STOP_WAIT"
    echo "Shutdown handler is completed"
}

trap "shutdown_gracefully" SIGTERM SIGINT

if [[ "$SERVICE_TYPE" == "full-node" ]]; then
  echo "INFO: This full node will run on the $NETWORK network."
else
  echo "INFO: This $SERVICE_TYPE node will run on the $NETWORK network."
fi

exec ./citrea --da-layer "$DA_LAYER" --genesis-paths "$GENESIS_PATH" "$SERVICE_TYPE" --network "$NETWORK" &
MAIN_PROCESS_PID=$!
sleep "$START_WAIT"
