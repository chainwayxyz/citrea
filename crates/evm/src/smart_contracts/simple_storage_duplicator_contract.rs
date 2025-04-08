use alloy_primitives::{Address, U256};
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// SimpleStorageContract wrapper.
sol! {
    #[sol(abi)]
    SimpleStorageDuplicator,
    "./src/evm/test_data/SimpleStorageDuplicator.abi"
}

/// SimpleStorageContract wrapper.
pub struct SimpleStorageDuplicatorContract {
    bytecode: Vec<u8>,
}

impl Default for SimpleStorageDuplicatorContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex =
                include_str!("../../../evm/src/evm/test_data/SimpleStorageDuplicator.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for SimpleStorageDuplicatorContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl SimpleStorageDuplicatorContract {
    /// SimpleStorage bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Getter for the smart contract.
    pub fn get_call_data(&self) -> Vec<u8> {
        SimpleStorageDuplicator::getCall {}.abi_encode()
    }
    /// Setter for the smart contract.
    pub fn set_call_data(&self, set_arg: u32, original_address: Address) -> Vec<u8> {
        SimpleStorageDuplicator::setCall {
            _num: U256::from(set_arg),
            _address: original_address,
        }
        .abi_encode()
    }
}
