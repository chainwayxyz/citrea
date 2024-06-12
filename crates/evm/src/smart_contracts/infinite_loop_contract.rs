use alloy_sol_types::{sol, SolCall};
use ethers_core::types::Bytes;

use super::TestContract;

// InfiniteLoop wrapper.
sol! {
    #[sol(abi)]
    InfiniteLoop,
    "./src/evm/test_data/InfiniteLoop.abi"
}

/// InfiniteLoopContract wrapper.
pub struct InfiniteLoopContract {
    bytecode: Bytes,
}

impl Default for InfiniteLoopContract {
    fn default() -> Self {
        let contract_data = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/InfiniteLoop.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self {
            bytecode: Bytes::from(contract_data),
        }
    }
}

impl TestContract for InfiniteLoopContract {
    fn byte_code(&self) -> Bytes {
        self.byte_code()
    }
}

impl InfiniteLoopContract {
    /// InfiniteLoop bytecode.
    pub fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }
    /// Calls InfiniteLoop::infiniteLoop.
    pub fn call_infinite_loop(&self) -> Bytes {
        InfiniteLoop::infiniteLoopCall {}.abi_encode().into()
    }
}
