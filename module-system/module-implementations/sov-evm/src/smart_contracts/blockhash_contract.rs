use std::any::Any;

use ethers_contract::BaseContract;
use ethers_core::types::Bytes;

use super::TestContract;
use super::{make_contract_from_abi, test_data_path};

/// Blockhash wrapper.
pub struct BlockHashContract {
    bytecode: Bytes,
    base_contract: BaseContract,
}

impl Default for BlockHashContract {
    fn default() -> Self {
        let contract_data = {
            let mut path = test_data_path();
            path.push("BlockHash.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
        };

        let contract = {
            let mut path = test_data_path();
            path.push("BlockHash.abi");

            make_contract_from_abi(path)
        };

        Self {
            bytecode: Bytes::from(contract_data),
            base_contract: contract,
        }
    }
}

impl TestContract for BlockHashContract {
    /// BlockhashContract bytecode.
    fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }
    /// Dynamically dispatch from trait. Downcast to BlockHashContract.
    fn as_any(&self) -> &dyn Any {
        self
    }
    /// Create the default instance of the smart contract.
    fn default_(&self) -> Self
    where
        Self: Sized,
    {
        Self::default()
    }
}

impl BlockHashContract {
    /// Function to get block hash of given block number.
    pub fn get_block_hash(&self, block_number: u64) -> Bytes {
        let get_arg = ethereum_types::U256::from(block_number);
        self.base_contract.encode("getBlockHash", get_arg).unwrap()
    }
}
