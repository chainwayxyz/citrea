use alloy_primitives::U256;
use alloy_sol_types::{sol, SolCall};
use ethers_core::types::Bytes;

// HiveContract wrapper.
sol! {
    #[sol(abi)]
    Hive,
    "./src/evm/test_data/HiveContract.abi"
}

/// HiveContract wrapper.
pub struct HiveContract {
    bytecode: Vec<u8>,
}

impl Default for HiveContract {
    fn default() -> Self {
        Self::new()
    }
}

impl HiveContract {
    /// Create a new instance of HiveContract.
    pub fn new() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/HiveContract.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
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
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }
}
