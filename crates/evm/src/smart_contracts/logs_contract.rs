use alloy_sol_types::{sol, SolCall};

use super::TestContract;

// Logs wrapper.
sol! {
    #[sol(abi)]
    Logs,
    "./src/evm/test_data/Logs.abi"
}

/// Logs wrapper.
pub struct LogsContract {
    bytecode: Vec<u8>,
}

impl Default for LogsContract {
    fn default() -> Self {
        let bytecode = {
            let bytecode_hex = include_str!("../../../evm/src/evm/test_data/Logs.bin");
            hex::decode(bytecode_hex).unwrap()
        };

        Self { bytecode }
    }
}

impl TestContract for LogsContract {
    fn byte_code(&self) -> Vec<u8> {
        self.bytecode.clone()
    }
}

impl LogsContract {
    /// Log publishing function of the smart contract.
    pub fn publish_event(&self, message: String) -> Vec<u8> {
        Logs::publishEventCall {
            _senderMessage: message,
        }
        .abi_encode()
    }
}
