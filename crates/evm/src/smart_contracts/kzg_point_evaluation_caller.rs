use alloy_primitives::Bytes;
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// KZGPointEvaluationCallerContract wrapper.
sol! {
    #[sol(abi)]
    KZGPointEvaluationCaller,
    "./src/evm/test_data/KZGPointEvaluationCaller.abi"
}

/// KZGPointEvaluationContract wrapper.
pub struct KZGPointEvaluationCallerContract {
    bytecode: Vec<u8>,
}

impl Default for KZGPointEvaluationCallerContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex =
                include_str!("../../../evm/src/evm/test_data/KZGPointEvaluationCaller.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for KZGPointEvaluationCallerContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl KZGPointEvaluationCallerContract {
    /// KZGPointEvaluation bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Claims the gift.
    pub fn call_kzg_point_evaluation(
        &self,
        input: Bytes, // 192 bytes
    ) -> Vec<u8> {
        KZGPointEvaluationCaller::verifyPointEvaluationCall { input }.abi_encode()
    }
}
