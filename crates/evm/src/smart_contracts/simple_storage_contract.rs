use alloy_primitives::U256;
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// SimpleStorageContract wrapper.
sol! {
    #[sol(abi)]
    SimpleStorage,
    "./src/evm/test_data/SimpleStorage.abi"
}

/// SimpleStorageContract wrapper.
pub struct SimpleStorageContract {
    bytecode: Vec<u8>,
}

impl Default for SimpleStorageContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/SimpleStorage.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for SimpleStorageContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl SimpleStorageContract {
    /// SimpleStorage bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Getter for the smart contract.
    pub fn get_call_data(&self) -> Vec<u8> {
        SimpleStorage::getCall {}.abi_encode()
    }
    /// Setter for the smart contract.
    pub fn set_call_data(&self, set_arg: u32) -> Vec<u8> {
        SimpleStorage::setCall {
            _num: U256::from(set_arg),
        }
        .abi_encode()
    }
    /// Failing call data to test revert.
    pub fn failing_function_call_data(&self) -> Vec<u8> {
        // Some random function signature.
        hex::decode("a5643bf2").unwrap()
    }
}
