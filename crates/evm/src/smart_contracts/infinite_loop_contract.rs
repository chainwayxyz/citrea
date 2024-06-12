use ethers_contract::BaseContract;
use ethers_core::types::Bytes;

use super::{make_contract_from_abi, test_data_path, TestContract};

/// InfiniteLoopContract wrapper.
pub struct InfiniteLoopContract {
    bytecode: Bytes,
    base_contract: BaseContract,
}

impl Default for InfiniteLoopContract {
    fn default() -> Self {
        let contract_data = {
            let mut path = test_data_path();
            path.push("InfiniteLoop.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
        };

        let contract = {
            let mut path = test_data_path();
            path.push("InfiniteLoop.abi");

            make_contract_from_abi(path)
        };

        Self {
            bytecode: Bytes::from(contract_data),
            base_contract: contract,
        }
    }
}

impl TestContract for InfiniteLoopContract {
    /// Caller bytecode.
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
        self.base_contract.encode("infiniteLoop", ()).unwrap()
    }
}
