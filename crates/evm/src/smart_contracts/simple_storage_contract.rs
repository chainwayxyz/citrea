use std::any::Any;

use ethers_contract::BaseContract;
use ethers_core::types::Bytes;

use super::{make_contract_from_abi, test_data_path, TestContract};

/// SimpleStorageContract wrapper.
pub struct SimpleStorageContract {
    bytecode: Bytes,
    base_contract: BaseContract,
}

impl Default for SimpleStorageContract {
    fn default() -> Self {
        let contract_data = {
            let mut path = test_data_path();
            path.push("SimpleStorage.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
        };

        let contract = {
            let mut path = test_data_path();
            path.push("SimpleStorage.abi");

            make_contract_from_abi(path)
        };

        Self {
            bytecode: Bytes::from(contract_data),
            base_contract: contract,
        }
    }
}

impl TestContract for SimpleStorageContract {
    /// SimpleStorage bytecode.
    fn byte_code(&self) -> Bytes {
        self.byte_code()
    }
    /// Dynamically dispatch from trait. Downcast to SimpleStorageContract.
    fn as_any(&self) -> &dyn Any {
        self
    }
    /// Create the default instance of the smart contract.
    fn default_(&self) -> Self
    where
        Self: Sized,
    {
        Self::default()
    }
}

impl SimpleStorageContract {
    /// SimpleStorage bytecode.
    pub fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }

    /// Getter for the smart contract.
    pub fn get_call_data(&self) -> Bytes {
        self.base_contract.encode("get", ()).unwrap()
    }
    /// Setter for the smart contract.
    pub fn set_call_data(&self, set_arg: u32) -> Bytes {
        let set_arg = ethereum_types::U256::from(set_arg);
        self.base_contract.encode("set", set_arg).unwrap()
    }
    /// Failing call data to test revert.
    pub fn failing_function_call_data(&self) -> Bytes {
        // Some random function signature.
        let data = hex::decode("a5643bf2").unwrap();
        Bytes::from(data)
    }
}
