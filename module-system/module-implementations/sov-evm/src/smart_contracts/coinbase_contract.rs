use std::any::Any;

use ethers_contract::BaseContract;
use ethers_core::types::Bytes;

use super::{make_contract_from_abi, test_data_path, TestContract};

/// CoinbaseContract wrapper.
pub struct CoinbaseContract {
    bytecode: Bytes,
    base_contract: BaseContract,
}

impl Default for CoinbaseContract {
    fn default() -> Self {
        let contract_data = {
            let mut path = test_data_path();
            path.push("Coinbase.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
        };

        let contract = {
            let mut path = test_data_path();
            path.push("Coinbase.abi");

            make_contract_from_abi(path)
        };

        Self {
            bytecode: Bytes::from(contract_data),
            base_contract: contract,
        }
    }
}

impl TestContract for CoinbaseContract {
    /// Coinbase bytecode.
    fn byte_code(&self) -> Bytes {
        self.byte_code()
    }
    /// Dynamically dispatch from trait. Downcast to CoinbaseContract.
    fn as_any(&self) -> &dyn Any {
        self
    }
    /// Create the default instance of the smart contract.
    fn default_(&self) -> Self
    where
        Self: Sized,
    {
        Self::default()
    }
}

impl CoinbaseContract {
    /// Coinbase bytecode.
    pub fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }

    /// Getter for the smart contract.
    pub fn reward_miner(&self) -> Bytes {
        self.base_contract.encode("rewardMiner", ()).unwrap()
    }
}
