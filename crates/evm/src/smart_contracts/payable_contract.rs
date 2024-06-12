use alloy_sol_types::{sol, SolCall};
use ethers::core::types::Bytes;

use super::{test_data_path, TestContract};

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
            let mut path = test_data_path();
            path.push("Payable.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
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
