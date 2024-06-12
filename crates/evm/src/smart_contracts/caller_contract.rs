use alloy_primitives::{Address, U256};
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// CallerContract wrapper.
sol! {
    #[sol(abi)]
    Caller,
    "./src/evm/test_data/Caller.abi"
}

/// CallerContract wrapper.
pub struct CallerContract {
    bytecode: Vec<u8>,
}

impl Default for CallerContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/Caller.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for CallerContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl CallerContract {
    /// Caller bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }
    /// Calls Getter of Caller Contract.
    pub fn call_get_call_data(&self, address: Address) -> Vec<u8> {
        Caller::callgetCall { addr: address }.abi_encode()
    }
    /// Calls Setter of Caller Contract.
    pub fn call_set_call_data(&self, address: Address, set_arg: u32) -> Vec<u8> {
        Caller::callsetCall {
            addr: address,
            num: U256::from(set_arg),
        }
        .abi_encode()
    }
}
