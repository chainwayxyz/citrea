use alloy_primitives::U256;
use alloy_sol_types::{sol, SolCall};
use ethers_core::types::Bytes;

use super::{test_data_path, TestContract};

// BlockHash wrapper.
sol! {
    #[sol(abi)]
    BlockHash,
    "./src/evm/test_data/BlockHash.abi"
}

/// Blockhash wrapper.
pub struct BlockHashContract {
    bytecode: Bytes,
}

impl Default for BlockHashContract {
    fn default() -> Self {
        let contract_data = {
            let mut path = test_data_path();
            path.push("BlockHash.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
        };

        Self {
            bytecode: Bytes::from(contract_data),
        }
    }
}

impl TestContract for BlockHashContract {
    fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }
}

impl BlockHashContract {
    /// Function to get block hash of given block number.
    pub fn get_block_hash(&self, block_number: u64) -> Bytes {
        BlockHash::getBlockHashCall {
            num: U256::from(block_number),
        }
        .abi_encode()
        .into()
    }
}
