use alloy_primitives::{Address, U256};
use alloy_sol_types::{sol, SolCall};
use ethers_core::types::Bytes;

use super::TestContract;

// SelfDestructor wrapper.
sol! {
    #[sol(abi)]
    SelfDestructor,
    "./src/evm/test_data/SelfDestructor.abi"
}

/// SelfDestructor wrapper.
pub struct SelfDestructorContract {
    bytecode: Vec<u8>,
}

impl Default for SelfDestructorContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/SelfDestructor.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for SelfDestructorContract {
    fn byte_code(&self) -> Vec<u8> {
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
