use alloy_primitives::U256;
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// BlockHash wrapper.
sol! {
    #[sol(abi)]
    BlockHash,
    "./src/evm/test_data/BlockHash.abi"
}

/// Blockhash wrapper.
pub struct BlockHashContract {
    bytecode: Vec<u8>,
}

impl Default for BlockHashContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/BlockHash.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for BlockHashContract {
    fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }
}

impl BlockHashContract {
    /// Function to get block hash of given block number.
    pub fn get_block_hash(&self, block_number: u64) -> Vec<u8> {
        BlockHash::getBlockHashCall {
            num: U256::from(block_number),
        }
        .abi_encode()
    }
}
