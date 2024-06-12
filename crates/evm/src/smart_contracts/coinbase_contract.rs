use alloy_sol_types::{sol, SolCall};
use ethers_core::types::Bytes;

use super::{test_data_path, TestContract};

// Coinbase wrapper.
sol! {
    #[sol(abi)]
    Coinbase,
    "./src/evm/test_data/Coinbase.abi"
}

/// CoinbaseContract wrapper.
pub struct CoinbaseContract {
    bytecode: Bytes,
}

impl Default for CoinbaseContract {
    fn default() -> Self {
        let contract_data = {
            let mut path = test_data_path();
            path.push("Coinbase.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
        };

        Self {
            bytecode: Bytes::from(contract_data),
        }
    }
}

impl TestContract for CoinbaseContract {
    fn byte_code(&self) -> Bytes {
        self.byte_code()
    }
}

impl CoinbaseContract {
    /// Coinbase bytecode.
    pub fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }

    /// Getter for the smart contract.
    pub fn reward_miner(&self) -> Bytes {
        Coinbase::rewardMinerCall {}.abi_encode().into()
    }
}
