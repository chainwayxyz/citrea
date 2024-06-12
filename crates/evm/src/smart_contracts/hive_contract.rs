use alloy_primitives::U256;
use alloy_sol_types::{sol, SolCall};
use ethers_core::types::Bytes;

use super::test_data_path;

// HiveContract wrapper.
sol! {
    #[sol(abi)]
    Hive,
    "./src/evm/test_data/HiveContract.abi"
}

/// HiveContract wrapper.
pub struct HiveContract {
    bytecode: Bytes,
}

impl Default for HiveContract {
    fn default() -> Self {
        Self::new()
    }
}

impl HiveContract {
    /// Create a new instance of HiveContract.
    pub fn new() -> Self {
        let contract_data = {
            let mut path = test_data_path();
            path.push("HiveContract.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
        };

        Self {
            bytecode: Bytes::from(contract_data),
        }
    }
    /// Calls ConstFunc of Hive Contract
    pub fn call_const_func(&self, a: u32, b: u32, c: u32) -> Bytes {
        Hive::constFuncCall {
            a: U256::from(a),
            b: U256::from(b),
            c: U256::from(c),
        }
        .abi_encode()
        .into()
    }

    /// Bytecode of the Hive Contract.
    pub fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }
}
