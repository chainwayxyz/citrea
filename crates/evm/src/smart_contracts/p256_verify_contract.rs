use alloy_primitives::Bytes;
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// P256VerifyCaller wrapper.
sol! {
    #[sol(abi)]
    P256VerifyCaller,
    "./src/evm/test_data/P256VerifyCaller.abi"
}

/// P256VerifyCaller wrapper.
pub struct P256VerifyCallerContract {
    bytecode: Vec<u8>,
}

impl Default for P256VerifyCallerContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/P256VerifyCaller.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for P256VerifyCallerContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl P256VerifyCallerContract {
    /// KZGPointEvaluation bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Call the precompile
    pub fn call_p256_verify(
        &self,
        input: Bytes, // 160 bytes
    ) -> Vec<u8> {
        P256VerifyCaller::p256VerifyCall { input }.abi_encode()
    }
}
