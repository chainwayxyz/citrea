use alloy_sol_types::{sol, SolCall};
use ethers_core::types::Bytes;

use super::{test_data_path, TestContract};

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
            let mut path = test_data_path();
            path.push("InfiniteLoop.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
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
