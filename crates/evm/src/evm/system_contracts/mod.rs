use alloy_primitives::{address, Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall};

// BitcoinLightClient wrapper.
sol! {
    #[sol(abi)]
    #[allow(missing_docs)]
    BitcoinLightClientContract,
    "./src/evm/system_contracts/out/BitcoinLightClient.sol/BitcoinLightClient.json"
}

/// BitcoinLightClient wrapper.
pub struct BitcoinLightClient {}

impl BitcoinLightClient {
    /// Return the address of the BitcoinLightClient contract.
    pub fn address() -> Address {
        address!("3100000000000000000000000000000000000001")
    }

    pub(crate) fn init(block_number: u64) -> Bytes {
        BitcoinLightClientContract::initializeBlockNumberCall {
            _blockNumber: U256::from(block_number),
        }
        .abi_encode()
        .into()
    }

    pub(crate) fn set_block_info(block_hash: [u8; 32], txs_commitments: [u8; 32]) -> Bytes {
        BitcoinLightClientContract::setBlockInfoCall {
            _blockHash: block_hash.into(),
            _witnessRoot: txs_commitments.into(),
        }
        .abi_encode()
        .into()
    }

    /// Return input data to query the block hash by block number mapping
    pub fn get_block_hash(block_number: u64) -> Bytes {
        BitcoinLightClientContract::getBlockHashCall {
            _blockNumber: U256::from(block_number),
        }
        .abi_encode()
        .into()
    }

    #[cfg(test)]
    pub(crate) fn get_witness_root_by_number(block_number: u64) -> Bytes {
        BitcoinLightClientContract::getWitnessRootByNumberCall {
            _blockNumber: U256::from(block_number),
        }
        .abi_encode()
        .into()
    }
}

// Bridge wrapper.
sol! {
    #[sol(abi)]
    #[allow(missing_docs)]
    BridgeContract,
    "./src/evm/system_contracts/out/Bridge.sol/Bridge.json"
}

/// Bridge wrapper.
pub struct Bridge {}

impl Bridge {
    /// Return the address of the Bridge contract.
    pub fn address() -> Address {
        address!("3100000000000000000000000000000000000002")
    }

    pub(crate) fn initialize() -> Bytes {
        // Hardcoded until better times.

        // params equal to:
        //
        // BridgeContract::initializeCall {
        //     _depositScript: hex!("d2205daf577048c5e5a9a75d0a924ed03e226c3304f4a2f01c65ca1dab73522e6b8bad206228eba653cf1819bcfc1bc858630e5ae373eec1a9924322a5fe8445c5e76027ad201521d65f64be3f71b71ca462220f13c77b251027f6ca443a483353a96fbce222ad200fabeed269694ee83d9b3343a571202e68af65d05feda61dbed0c4bdb256a6eaad2000326d6f721c03dc5f1d8817d8f8ee890a95a2eeda0d4d9a01b1cc9b7b1b724dac00630663697472656114").into(),
        //     _scriptSuffix: hex!("0800000000000f424068").into(),
        //     _requiredSigsCount: U256::from(5),
        //     _owner: address!("f9725b63fe14efaf7cc705ba4e5c55a03d50e940"),
        // }
        // .abi_encode()
        let params = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 1, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 249, 114, 91, 99,
            254, 20, 239, 175, 124, 199, 5, 186, 78, 92, 85, 160, 61, 80, 233, 64, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 181, 210,
            32, 93, 175, 87, 112, 72, 197, 229, 169, 167, 93, 10, 146, 78, 208, 62, 34, 108, 51, 4,
            244, 162, 240, 28, 101, 202, 29, 171, 115, 82, 46, 107, 139, 173, 32, 98, 40, 235, 166,
            83, 207, 24, 25, 188, 252, 27, 200, 88, 99, 14, 90, 227, 115, 238, 193, 169, 146, 67,
            34, 165, 254, 132, 69, 197, 231, 96, 39, 173, 32, 21, 33, 214, 95, 100, 190, 63, 113,
            183, 28, 164, 98, 34, 15, 19, 199, 123, 37, 16, 39, 246, 202, 68, 58, 72, 51, 83, 169,
            111, 188, 226, 34, 173, 32, 15, 171, 238, 210, 105, 105, 78, 232, 61, 155, 51, 67, 165,
            113, 32, 46, 104, 175, 101, 208, 95, 237, 166, 29, 190, 208, 196, 189, 178, 86, 166,
            234, 173, 32, 0, 50, 109, 111, 114, 28, 3, 220, 95, 29, 136, 23, 216, 248, 238, 137,
            10, 149, 162, 238, 218, 13, 77, 154, 1, 177, 204, 155, 123, 27, 114, 77, 172, 0, 99, 6,
            99, 105, 116, 114, 101, 97, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 8, 0, 0, 0,
            0, 0, 15, 66, 64, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ];

        let mut func_selector = Vec::with_capacity(4 + params.len());
        func_selector.extend(BridgeContract::initializeCall::SELECTOR);
        func_selector.extend(params);
        func_selector.into()
    }

    /// Return data to deposit
    pub fn deposit(params: Vec<u8>) -> Bytes {
        // Params can be read by `BridgeContract::depositCall::abi_decode_raw(&params, true)`
        let mut func_selector = Vec::with_capacity(4 + params.len());
        func_selector.extend(BridgeContract::depositCall::SELECTOR);
        func_selector.extend(params);
        func_selector.into()
    }
}
