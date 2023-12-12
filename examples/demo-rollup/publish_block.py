# script to auto send 'eth_publishBatch' requests every 2 seconds
# TODO: read sequencer url from .toml files

import requests
from time import sleep
while True:
    sleep(2)

    requests.post("http://0.0.0.0:12345", json={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_publishBatch",
        "params": []
    })