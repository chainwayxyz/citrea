use alloy_sol_types::{sol, SolCall};
use ethers::core::types::Bytes;

use super::TestContract;

// Payable wrapper.
sol! {
    #[sol(abi)]
    Payable,
    "./src/evm/test_data/Payable.abi"
}

/// SimplePayableContract wrapper.
pub struct SimplePayableContract {
    bytecode: Bytes,
}

impl Default for SimplePayableContract {
    fn default() -> Self {
        let contract_data = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/Payable.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self {
            bytecode: Bytes::from(contract_data),
        }
    }
}

impl TestContract for SimplePayableContract {
    fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }
}

impl SimplePayableContract {
    /// Getter for the contract's balance.
    pub fn get_balance(&self) -> Bytes {
        Payable::getBalanceCall {}.abi_encode().into()
    }

    /// Withdraw function call data.
    pub fn withdraw(&self) -> Bytes {
        Payable::withdrawCall {}.abi_encode().into()
    }
}
