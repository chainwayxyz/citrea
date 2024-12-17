use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// McopyContract wrapper.
sol! {
    #[sol(abi)]
    Mcopy,
    "./src/evm/test_data/Mcopy.abi"
}

/// McopyContract wrapper.
pub struct McopyContract {
    bytecode: Vec<u8>,
}

impl Default for McopyContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/Mcopy.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for McopyContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl McopyContract {
    /// Mcopy bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Claims the gift.
    pub fn call_mcopy(&self) -> Vec<u8> {
        Mcopy::memoryCopyCall {}.abi_encode()
    }
}
