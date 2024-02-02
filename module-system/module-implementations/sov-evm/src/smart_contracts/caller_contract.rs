use std::any::Any;

use ethers_contract::BaseContract;
use ethers_core::types::Bytes;
use reth_primitives::Address;

use super::{make_contract_from_abi, test_data_path, TestContract};

/// CallerContract wrapper.
pub struct CallerContract {
    bytecode: Bytes,
    base_contract: BaseContract,
}

impl Default for CallerContract {
    fn default() -> Self {
        let contract_data = {
            let mut path = test_data_path();
            path.push("Caller.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
        };

        let contract = {
            let mut path = test_data_path();
            path.push("Caller.abi");

            make_contract_from_abi(path)
        };

        Self {
            bytecode: Bytes::from(contract_data),
            base_contract: contract,
        }
    }
}

impl TestContract for CallerContract {
    /// Caller bytecode.
    fn byte_code(&self) -> Bytes {
        self.byte_code()
    }
    /// Dynamically dispatch from trait. Downcast to CallerContract.
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

impl CallerContract {
    /// Caller bytecode.
    pub fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }
    /// Calls Getter of Simple Storage Contract.
    pub fn call_get_call_data(&self, address: Address) -> Bytes {
        let address = ethereum_types::Address::from_slice(address.as_ref());
        self.base_contract.encode("callget", address).unwrap()
    }
    /// Calls Setter of Simple Storage Contract.
    pub fn call_set_call_data(&self, address: Address, set_arg: u32) -> Bytes {
        let set_arg = ethereum_types::U256::from(set_arg);
        let address = ethereum_types::Address::from_slice(address.as_ref());
        let args = (address, set_arg);
        self.base_contract.encode("callset", args).unwrap()
    }
}
