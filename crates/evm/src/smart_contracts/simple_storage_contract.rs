use alloy_primitives::U256;
use alloy_sol_types::{sol, SolCall};
use ethers_core::types::Bytes;

use super::TestContract;

// SimpleStorageContract wrapper.
sol! {
    #[sol(abi)]
    SimpleStorage,
    "./src/evm/test_data/SimpleStorage.abi"
}

/// SimpleStorageContract wrapper.
pub struct SimpleStorageContract {
    bytecode: Bytes,
}

impl Default for SimpleStorageContract {
    fn default() -> Self {
        let contract_data = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/SimpleStorage.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self {
            bytecode: Bytes::from(contract_data),
        }
    }
}

impl TestContract for SimpleStorageContract {
    fn byte_code(&self) -> Bytes {
        self.byte_code()
    }
}

impl SimpleStorageContract {
    /// SimpleStorage bytecode.
    pub fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }

    /// Getter for the smart contract.
    pub fn get_call_data(&self) -> Bytes {
        SimpleStorage::getCall {}.abi_encode().into()
    }
    /// Setter for the smart contract.
    pub fn set_call_data(&self, set_arg: u32) -> Bytes {
        SimpleStorage::setCall {
            _num: U256::from(set_arg),
        }
        .abi_encode()
        .into()
    }
    /// Failing call data to test revert.
    pub fn failing_function_call_data(&self) -> Bytes {
        // Some random function signature.
        hex::decode("a5643bf2").unwrap().into()
    }
}
