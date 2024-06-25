use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// Coinbase wrapper.
sol! {
    #[sol(abi)]
    Coinbase,
    "./src/evm/test_data/Coinbase.abi"
}

/// CoinbaseContract wrapper.
pub struct CoinbaseContract {
    bytecode: Vec<u8>,
}

impl Default for CoinbaseContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/Coinbase.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for CoinbaseContract {
    fn byte_code(&self) -> Vec<u8> {
        self.byte_code()
    }
}

impl CoinbaseContract {
    /// Coinbase bytecode.
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Getter for the smart contract.
    pub fn reward_miner(&self) -> Vec<u8> {
        Coinbase::rewardMinerCall {}.abi_encode()
    }
}
