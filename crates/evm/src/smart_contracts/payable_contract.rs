use ethers::contract::BaseContract;
use ethers::core::types::Bytes;

use super::{make_contract_from_abi, test_data_path, TestContract};

/// SimplePayableContract wrapper.
pub struct SimplePayableContract {
    bytecode: Bytes,
    base_contract: BaseContract,
}

impl Default for SimplePayableContract {
    fn default() -> Self {
        let contract_data = {
            let mut path = test_data_path();
            path.push("Payable.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
        };

        let contract = {
            let mut path = test_data_path();
            path.push("Payable.abi");

            make_contract_from_abi(path)
        };

        Self {
            bytecode: Bytes::from(contract_data),
            base_contract: contract,
        }
    }
}

impl TestContract for SimplePayableContract {
    fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }
    fn default_(&self) -> Self
    where
        Self: Sized,
    {
        Self::default()
    }
}

impl SimplePayableContract {
    /// Getter for the contract's balance.
    pub fn get_balance(&self) -> Bytes {
        self.base_contract.encode("getBalance", ()).unwrap()
    }

    /// Withdraw function call data.
    pub fn withdraw(&self) -> Bytes {
        self.base_contract.encode("withdraw", ()).unwrap()
    }
}
