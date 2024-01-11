use std::any::Any;

use ethers_contract::BaseContract;
use ethers_core::types::Bytes;
use reth_primitives::Address;

use super::{make_contract_from_abi, test_data_path, TestContract};

/// SelfDestructor wrapper.
pub struct SelfDestructorContract {
    bytecode: Bytes,
    base_contract: BaseContract,
}

impl Default for SelfDestructorContract {
    fn default() -> Self {
        let contract_data = {
            let mut path = test_data_path();
            path.push("SelfDestructor.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
        };

        let contract = {
            let mut path = test_data_path();
            path.push("SelfDestructor.abi");

            make_contract_from_abi(path)
        };

        Self {
            bytecode: Bytes::from(contract_data),
            base_contract: contract,
        }
    }
}

impl TestContract for SelfDestructorContract {
    /// SimpleStorage bytecode.
    fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }
    /// Dynamically dispatch from trait. Downcast to SelfDestructorContract.
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

impl SelfDestructorContract {
    /// Setter of the smart contract.
    pub fn set_call_data(&self, val: u32) -> Bytes {
        let set_arg = ethereum_types::U256::from(val);
        self.base_contract.encode("set", set_arg).unwrap()
    }
    /// Selfdestructor of the smart contract.
    pub fn selfdestruct(&self, to: Address) -> Bytes {
        let set_arg = ethereum_types::Address::from_slice(&to.as_ref());
        self.base_contract.encode("die", set_arg).unwrap()
    }
}
