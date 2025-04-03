use alloy_primitives::Bytes;
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// SchnorrVerifyCaller wrapper.
sol! {
    #[sol(abi)]
    SchnorrVerifyCaller,
    "./src/evm/test_data/SchnorrVerifyCaller.abi"
}

/// SchnorrVerifyCaller wrapper.
pub struct SchnorrVerifyCallerContract {
    bytecode: Vec<u8>,
}

impl Default for SchnorrVerifyCallerContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex =
                include_str!("../../../evm/src/evm/test_data/SchnorrVerifyCaller.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for SchnorrVerifyCallerContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl SchnorrVerifyCallerContract {
    /// SchnorrVerifyCaller bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Call the precompile
    pub fn call_schnorr_verify(
        &self,
        input: Bytes, // 160 bytes
    ) -> Vec<u8> {
        SchnorrVerifyCaller::schnorrVerifyCall { input }.abi_encode()
    }
}
