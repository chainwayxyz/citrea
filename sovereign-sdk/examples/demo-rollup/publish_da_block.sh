# script to auto send 'eth_publishBatch' requests every 2 seconds
# TODO: read sequencer url from .toml files

SLEEP_DURATION=60
SEQUENCER_URL='http://0.0.0.0:12345'

echo "Publishing da blocks every 60 seconds"
echo "Sequencer URL: $SEQUENCER_URL"

while true; do
    sleep $SLEEP_DURATION

    curl -s -o /dev/null --location $SEQUENCER_URL \
        --header 'Content-Type: application/json' \
        --data '{
        "jsonrpc": "2.0",
        "method": "da_publishBlock",
        "params": [],
        "id": 1
        }'

done
