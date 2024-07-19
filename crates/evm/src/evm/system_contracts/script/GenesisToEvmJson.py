import json
import sys
import time
import asyncio
i = 0 
async def main():
    global i
    print(1)
    with open(sys.argv[1], "r") as file:
        data = json.load(file)
    print(2)
    i+=1
    # Sort the data by key
    data = {k: data[k] for k in sorted(data)}
    print(3)
    i+=1
    new_data = []
    print(4)
    i+=1
    for key in data:
        new_data.append({
            "address": key,
            "balance": data[key]["balance"],
            "code": data[key]["code"]
        })
        if data[key]["storage"] != {}:
            new_data[-1]["storage"] = data[key]["storage"]
    print(5)
    i+=1
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
    print(6)
    i+=1
    with open(sys.argv[2], "w") as file:
        json.dump(evm_json, file, indent=2)
    print(7)
    i+=1
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
    print(8)
    i+=1

    # check if the files are equal

    for path in paths:
        with open(path, "r") as file:
            data = json.load(file)

            if path == "../../../../../resources/genesis/bitcoin-regtest/evm.json":
                print("111111\n\n\n\n\n")
                # print(data)
                print("222222\n\n\n\n\n")
                # print(evm_json)
                print("3333333\n\n\n\n\n")
            if path == "../../../../../resources/test-data/integration-tests-low-block-gas-limit/evm.json":
                new_evm_json = evm_json.copy()
                new_evm_json["block_gas_limit"] = 1500000
                if json.dumps(new_evm_json, indent=None, separators=(',', ':')) != json.dumps(data, indent=None, separators=(',', ':')):
                    print("Not Eq", path)            
                continue
            if json.dumps(evm_json, indent=None, separators=(',', ':')) != json.dumps(data, indent=None, separators=(',', ':')):
                print("Not Eq", path)

    print(9)
    i+=1
    print(i)
    await asyncio.sleep(5)
    print(10)
    for path in paths:
        print("W1")
        with open(path, "w+") as file:
            print("W2")
            if path == "../../../../../resources/test-data/integration-tests-low-block-gas-limit/evm.json":
                new_evm_json = evm_json.copy()
                new_evm_json["block_gas_limit"] = 1500000
                json.dump(new_evm_json, file, indent=2)
                print("W3")
                continue
            json.dump(evm_json, file, indent=2)
            print("W3")
    print(11)

if __name__ == '__main__':

    asyncio.run(main()) 