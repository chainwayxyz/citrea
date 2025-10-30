use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// MinimalBatchWallet contract wrapper
sol! {
    #[sol(abi)]
    MinimalBatchWallet,
    "./src/evm/test_data/MinimalBatchWallet.abi"
}

/// Execution struct matching the contract
#[derive(Debug, Clone)]
pub struct Execution {
    /// Target contract address for the call
    pub target: Address,
    /// ETH value to send with the call
    pub value: U256,
    /// Call data to send to the target
    pub call_data: Vec<u8>,
}

/// MinimalBatchWallet contract wrapper
pub struct MinimalBatchWalletContract {
    bytecode: Vec<u8>,
}

impl Default for MinimalBatchWalletContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../evm/test_data/MinimalBatchWallet.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for MinimalBatchWalletContract {
    fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }
}

impl MinimalBatchWalletContract {
    /// Mode for batch execution with revert on failure
    pub const MODE_BATCH_REVERT: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x01,
    ];

    /// Mode for single execution with revert on failure
    pub const MODE_SINGLE_REVERT: [u8; 32] = [0u8; 32];

    /// Get bytecode
    pub fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }

    /// Create call data for execute() with a single execution
    pub fn execute_single_call_data(
        &self,
        target: Address,
        value: U256,
        call_data: Vec<u8>,
    ) -> Vec<u8> {
        // Encode as tuple (address, uint256, bytes)
        let execution_data =
            alloy_sol_types::SolValue::abi_encode_params(&(target, value, Bytes::from(call_data)));

        MinimalBatchWallet::executeCall {
            mode: Self::MODE_SINGLE_REVERT.into(),
            executionData: Bytes::from(execution_data),
        }
        .abi_encode()
    }

    /// Create call data for execute() with batch of executions
    /// This is the critical function that triggers the gas bug
    pub fn execute_batch_call_data(&self, executions: Vec<Execution>) -> Vec<u8> {
        // Split executions into three separate arrays (address[], uint256[], bytes[])
        // This matches Solidity's expected format: (address[], uint256[], bytes[])
        let targets: Vec<Address> = executions.iter().map(|e| e.target).collect();
        let values: Vec<U256> = executions.iter().map(|e| e.value).collect();
        let datas: Vec<Bytes> = executions
            .iter()
            .map(|e| Bytes::from(e.call_data.clone()))
            .collect();

        // Encode as tuple of three arrays: (address[], uint256[], bytes[])
        let execution_data =
            alloy_sol_types::SolValue::abi_encode_params(&(targets, values, datas));

        MinimalBatchWallet::executeCall {
            mode: Self::MODE_BATCH_REVERT.into(),
            executionData: Bytes::from(execution_data),
        }
        .abi_encode()
    }
}
