use alloy_primitives::Bytes;
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// P256VerifyCaller wrapper.
sol! {
    #[sol(abi)]
    G1AddCaller,
    "./src/evm/test_data/G1AddCaller.abi"
}

/// P256VerifyCaller wrapper.
pub struct G1AddCallerContract {
    bytecode: Vec<u8>,
}

impl Default for G1AddCallerContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/G1AddCaller.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for G1AddCallerContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl G1AddCallerContract {
    /// P256VerifyCaller bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Call the precompile
    pub fn call_g1_add(
        &self,
        input: Bytes, // 160 bytes
    ) -> Vec<u8> {
        G1AddCaller::g1AddCall { input }.abi_encode()
    }

    /// Gets result saved
    pub fn get_result(&self) -> Vec<u8> {
        G1AddCaller::g1AddResultCall {}.abi_encode()
    }
}
