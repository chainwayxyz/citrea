use alloy_primitives::{Address, U256};
use alloy_sol_types::{sol, SolCall};
use ethers_core::types::Bytes;

use super::{test_data_path, TestContract};

// SelfDestructor wrapper.
sol! {
    #[sol(abi)]
    SelfDestructor,
    "./src/evm/test_data/SelfDestructor.abi"
}

/// SelfDestructor wrapper.
pub struct SelfDestructorContract {
    bytecode: Bytes,
}

impl Default for SelfDestructorContract {
    fn default() -> Self {
        let contract_data = {
            let mut path = test_data_path();
            path.push("SelfDestructor.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
        };

        Self {
            bytecode: Bytes::from(contract_data),
        }
    }
}

impl TestContract for SelfDestructorContract {
    fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }
}

impl SelfDestructorContract {
    /// Setter of the smart contract.
    pub fn set_call_data(&self, val: u32) -> Bytes {
        SelfDestructor::setCall {
            _x: U256::from(val),
        }
        .abi_encode()
        .into()
    }
    /// Selfdestructor of the smart contract.
    pub fn selfdestruct(&self, to: Address) -> Bytes {
        SelfDestructor::dieCall { to }.abi_encode().into()
    }
}
