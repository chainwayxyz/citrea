use alloy_sol_types::{sol, SolCall};
use ethers_core::types::Bytes;

use super::TestContract;

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
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/Coinbase.bin");
            hex::decode(bytecode_hex).unwrap()
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
