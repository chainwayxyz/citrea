#!/usr/bin/python3

import os
import json

# If this script fails:
# - update crates/evm/src/evm/system_contracts/mod.rs accordingly

test_script_dir = os.path.dirname(os.path.realpath(__file__))
artifact_dir = test_script_dir + "/../out/"


def assert_hash(contract, id, hash, expected_hash):
    msg = f"{contract}::{id} must have hash '{expected_hash}', but '{hash}' is set instead."
    assert hash == expected_hash, msg


sys_contracts = {
    "BitcoinLightClient": {
        "initializeBlockNumber(uint256)": "1f578333",
        "setBlockInfo(bytes32,bytes32)": "0e27bc11",
        "getBlockHash(uint256)": "ee82ac5e",
        "getWitnessRootByNumber(uint256)": "61b207e2",
    }
}

for contract, exp in sys_contracts.items():
    with open(artifact_dir + f"{contract}.sol/{contract}.json") as f:
        abi = json.load(f)
        ids = abi["methodIdentifiers"]

        for id in exp:
            assert id in ids, f"'{id}' not found in {contract} ABI"

        for id, hash in ids.items():
            for exp_id, exp_hash in exp.items():
                if id.startswith(exp_id):
                    assert_hash(contract, id, hash, exp_hash)
