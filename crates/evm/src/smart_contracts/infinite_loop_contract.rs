use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// InfiniteLoop wrapper.
sol! {
    #[sol(abi)]
    InfiniteLoop,
    "./src/evm/test_data/InfiniteLoop.abi"
}

/// InfiniteLoopContract wrapper.
pub struct InfiniteLoopContract {
    bytecode: Vec<u8>,
}

impl Default for InfiniteLoopContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/InfiniteLoop.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for InfiniteLoopContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl InfiniteLoopContract {
    /// InfiniteLoop bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }
    /// Calls InfiniteLoop::infiniteLoop.
    pub fn call_infinite_loop(&self) -> Vec<u8> {
        InfiniteLoop::infiniteLoopCall {}.abi_encode()
    }
}
