import json
import sys
import os

with open(sys.argv[1], "r") as file:
    data = json.load(file)

isProd = True if (sys.argv[3] == "true") else False

# Sort the data by key
data = {k: data[k] for k in sorted(data)}

new_data = []

for key in data:
    new_data.append({
        "address": key,
        "balance": data[key]["balance"],
        "code": data[key]["code"]
    })
    if data[key]["storage"] != {}:
        new_data[-1]["storage"] = data[key]["storage"]

evm_json = {}
evm_json["data"] = new_data
if not isProd:
    evm_json["chain_id"] = 5655
else:
    if os.environ.get("CHAIN_ID") is None:
        raise Exception("CHAIN_ID environment variable is not set")
    evm_json["chain_id"] = os.getenv("CHAIN_ID")
evm_json["limit_contract_code_size"] = None
evm_json["spec"] = {"0": "SHANGHAI"}
evm_json["coinbase"] = "0x3100000000000000000000000000000000000005"
evm_json["starting_base_fee"] = 1000000000
evm_json["block_gas_limit"] = 30000000
evm_json["base_fee_params"] = {"max_change_denominator": 8, "elasticity_multiplier" : 2}
evm_json["difficulty"] = 0
evm_json["extra_data"] = "0x"
evm_json["timestamp"] = 0
evm_json["nonce"] = 0

with open(sys.argv[2], "w") as file:
    json.dump(evm_json, file, indent=2)

# Copy evm.json to following paths
paths = [
    "../../../../../resources/genesis/bitcoin-regtest/evm.json",
    "../../../../../resources/genesis/mock/evm.json",
    "../../../../../resources/genesis/mock-dockerized/evm.json",
    "../../../../../resources/test-data/demo-tests/bitcoin-regtest/evm.json",
    "../../../../../resources/test-data/demo-tests/mock/evm.json",
    "../../../../../resources/test-data/integration-tests/evm.json",
    "../../../../../resources/test-data/integration-tests-low-block-gas-limit/evm.json",
    "../../../../../resources/test-data/integration-tests-low-max-l2-blocks-per-l1/evm.json"
]

if not isProd:
    for path in paths:
        with open(path, "w") as file:
            if path == "../../../../../resources/test-data/integration-tests-low-block-gas-limit/evm.json":
                new_evm_json = evm_json.copy()
                new_evm_json["block_gas_limit"] = 1500000
                json.dump(new_evm_json, file, indent=2)
                continue
            json.dump(evm_json, file, indent=2)