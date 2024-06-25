use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// Payable wrapper.
sol! {
    #[sol(abi)]
    Payable,
    "./src/evm/test_data/Payable.abi"
}

/// SimplePayableContract wrapper.
pub struct SimplePayableContract {
    bytecode: Vec<u8>,
}

impl Default for SimplePayableContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/Payable.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for SimplePayableContract {
    fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }
}

impl SimplePayableContract {
    /// Getter for the contract's balance.
    pub fn get_balance(&self) -> Vec<u8> {
        Payable::getBalanceCall {}.abi_encode()
    }

    /// Withdraw function call data.
    pub fn withdraw(&self) -> Vec<u8> {
        Payable::withdrawCall {}.abi_encode()
    }
}
