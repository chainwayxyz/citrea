# script to auto send 'eth_publishBatch' requests every 2 seconds
# TODO: read sequencer url from .toml files

SLEEP_DURATION=10
SEQUENCER_URL='http://0.0.0.0:12345'


echo "Publishing blocks every 2 seconds";
echo "Sequencer URL: $SEQUENCER_URL";

while true;
do
    curl -s -o /dev/null --location $SEQUENCER_URL \
    --header 'Content-Type: application/json' \
    --data '{
        "jsonrpc": "2.0",
        "method": "eth_publishBatch",
        "params": [],
        "id": 1
        }';

    sleep $SLEEP_DURATION;
done

