# script used for devnet fork1 data pull for setting constants in guests

import requests
import json

def json_rpc_req(method, params):
    url = "https://rpc.testnet.citrea.xyz"
    payload = json.dumps({
      "jsonrpc": "2.0",
      "id": 1,
      "method": method,
      "params": params
    })
    headers = {
      'Content-Type': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    return response.json()["result"]

# Get head l2 block
def get_head_l2_block():
    return json_rpc_req("ledger_getHeadL2Block", [])

# Get l2 block by height
def get_l2_block_by_height(height):
    return json_rpc_req("ledger_getL2BlockByNumber", [height])

# Get Sequencer commitments on DA slot by number
def get_sequencer_commitments_on_slot_by_number(number):
    return json_rpc_req("ledger_getSequencerCommitmentsOnSlotByNumber", [number])


print("Initializing data pull...")

head_l2 = get_head_l2_block()

print("Head l2 block height:\t", head_l2['l2Height'], "\nL1 height:\t", head_l2['daSlotHeight'])

print("Fetching latest sequencer commitment")

start = head_l2['daSlotHeight']

for i in range(start, 0, -1):
    sequencer_commitments = get_sequencer_commitments_on_slot_by_number(i)

    if sequencer_commitments is not None:
        print("Found", len(sequencer_commitments),  "sequencer commitment(s) on slot:\t", i, "using first one.")
        sequencer_commitment = sequencer_commitments[0]

        print("Sequencer commitment start:\t", sequencer_commitment['l2StartBlockNumber'], "\tend:\t", sequencer_commitment['l2EndBlockNumber'])

        fork1_genesis_state_root_height = int(sequencer_commitment['l2StartBlockNumber'], 16) - 1

        print("Genesis state root height:\t", fork1_genesis_state_root_height)

        genesis_l2_block = get_l2_block_by_height(fork1_genesis_state_root_height)

        print("Genesis state root:\t", genesis_l2_block['stateRoot'])
        print("Batch prover start proving at DA height:\t", i)
        print("Light client prover start proving at DA height:\t", i, "\t Fill its constants with:\t", i-1)

        break
