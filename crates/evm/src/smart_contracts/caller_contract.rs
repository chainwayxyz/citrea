use alloy_primitives::U256;
use alloy_sol_types::{sol, SolCall};
use ethers_core::types::Bytes;
use reth_primitives::Address;

use super::TestContract;

// CallerContract wrapper.
sol! {
    #[sol(abi)]
    Caller,
    "./src/evm/test_data/Caller.abi"
}

/// CallerContract wrapper.
pub struct CallerContract {
    bytecode: Bytes,
}

impl Default for CallerContract {
    fn default() -> Self {
        let contract_data = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/Caller.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self {
            bytecode: Bytes::from(contract_data),
        }
    }
}

impl TestContract for CallerContract {
    fn byte_code(&self) -> Bytes {
        self.byte_code()
    }
}

impl CallerContract {
    /// Caller bytecode.
    pub fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }
    /// Calls Getter of Caller Contract.
    pub fn call_get_call_data(&self, address: Address) -> Bytes {
        Caller::callgetCall { addr: address }.abi_encode().into()
    }
    /// Calls Setter of Caller Contract.
    pub fn call_set_call_data(&self, address: Address, set_arg: u32) -> Bytes {
        Caller::callsetCall {
            addr: address,
            num: U256::from(set_arg),
        }
        .abi_encode()
        .into()
    }
}
