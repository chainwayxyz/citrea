import json
import sys

with open(sys.argv[1], "r") as file:
    data = json.load(file)

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
evm_json["chain_id"] = 5655
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