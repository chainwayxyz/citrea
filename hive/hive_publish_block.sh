# script to auto send 'citrea_testPublishBlock' requests every 2 seconds
# TODO: read sequencer url from .toml files

SLEEP_DURATION=2
SEQUENCER_URL='http://0.0.0.0:8545'

echo "Publishing blocks every 2 seconds"
echo "Sequencer URL: $SEQUENCER_URL"

while true; do
    curl -s -o /dev/null --location $SEQUENCER_URL \
        --header 'Content-Type: application/json' \
        --data '{
        "jsonrpc": "2.0", 
        "method": "citrea_testPublishBlock", 
        "params": [], 
        "id": 1
        }'

    sleep $SLEEP_DURATION
done
