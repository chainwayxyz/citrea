use ethers_contract::BaseContract;
use ethers_core::types::Bytes;

use super::{make_contract_from_abi, test_data_path};

/// CallerContract wrapper.
pub struct HiveContract {
    bytecode: Bytes,
    base_contract: BaseContract,
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

        let base_contract = {
            let mut path = test_data_path();
            path.push("HiveContract.abi");

            make_contract_from_abi(path)
        };
        Self {
            bytecode: Bytes::from(contract_data),
            base_contract,
        }
    }
    /// Calls ConstFunc of Hive Contract
    pub fn call_const_func(&self, a: u32, b: u32, c: u32) -> Bytes {
        let arg_a = ethereum_types::U256::from(a);
        let arg_b = ethereum_types::U256::from(b);
        let arg_c = ethereum_types::U256::from(c);
        let args = (arg_a, arg_b, arg_c);
        self.base_contract.encode("constFunc", args).unwrap()
    }

    /// Bytecode of the Hive Contract.
    pub fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }
}
