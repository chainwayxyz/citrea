use alloy_primitives::{Bytes, U256};
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// SchnorrVerifyCaller wrapper.
sol! {
    #[sol(abi)]
    CrazyKeccak,
    "./src/evm/test_data/CrazyKeccak.abi"
}

/// CrazyKeccak wrapper.
pub struct CrazyKeccakContract {
    bytecode: Vec<u8>,
}

impl Default for CrazyKeccakContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/CrazyKeccak.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for CrazyKeccakContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl CrazyKeccakContract {
    /// CrazyKeccak bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Call the precompile
    pub fn call_crazy_keccak(&self, times: u64) -> Vec<u8> {
        CrazyKeccak::keccakCall {
            times: U256::from(times),
        }
        .abi_encode()
    }
}
