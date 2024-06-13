use alloy_primitives::{address, hex, Address, Bytes, U256};
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
    #[derive(Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
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
        BridgeContract::initializeCall {
            _depositScript: hex!("d2205daf577048c5e5a9a75d0a924ed03e226c3304f4a2f01c65ca1dab73522e6b8bad206228eba653cf1819bcfc1bc858630e5ae373eec1a9924322a5fe8445c5e76027ad201521d65f64be3f71b71ca462220f13c77b251027f6ca443a483353a96fbce222ad200fabeed269694ee83d9b3343a571202e68af65d05feda61dbed0c4bdb256a6eaad2000326d6f721c03dc5f1d8817d8f8ee890a95a2eeda0d4d9a01b1cc9b7b1b724dac00630663697472656114").into(),
            _scriptSuffix: hex!("0800000000000f424068").into(),
            _requiredSigsCount: U256::from(5),
            _owner: address!("f9725b63fe14efaf7cc705ba4e5c55a03d50e940"),
        }
        .abi_encode()
        .into()
    }

    /// Return data to deposit
    pub fn deposit(params: BridgeContract::DepositParams) -> Bytes {
        BridgeContract::depositCall { p: params }
            .abi_encode()
            .into()
    }
}
