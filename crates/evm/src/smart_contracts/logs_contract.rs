use alloy_sol_types::{sol, SolCall};
use ethers_core::types::Bytes;

use super::TestContract;

// Logs wrapper.
sol! {
    #[sol(abi)]
    Logs,
    "./src/evm/test_data/Logs.abi"
}

/// Logs wrapper.
pub struct LogsContract {
    bytecode: Bytes,
}

impl Default for LogsContract {
    fn default() -> Self {
        let contract_data = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/Logs.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self {
            bytecode: Bytes::from(contract_data),
        }
    }
}

impl TestContract for LogsContract {
    fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }
}

impl LogsContract {
    /// Log publishing function of the smart contract.
    pub fn publish_event(&self, message: String) -> Bytes {
        Logs::publishEventCall {
            _senderMessage: message,
        }
        .abi_encode()
        .into()
    }
}
