use alloy_sol_types::{sol, SolCall};
use ethers_core::types::Bytes;

use super::{test_data_path, TestContract};

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
            let mut path = test_data_path();
            path.push("Logs.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
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
