use core::result::Result;

use alloy_sol_types::{sol, SolCall, SolEvent};

use super::TestContract;

sol! {
    #[sol(abi)]
    Logs,
    "./src/evm/test_data/Logs.abi"
}

pub use Logs::{AnotherLog as AnotherLogEvent, Log as LogEvent};

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

    /// Decode Log event of the Logs smart contract.
    pub fn decode_log_event(
        log: &alloy_primitives::Log,
    ) -> Result<alloy_primitives::Log<Logs::Log>, alloy_sol_types::Error> {
        Logs::Log::decode_log(log, true)
    }

    /// Decode AnotherLog event of the Logs smart contract.
    pub fn decode_another_log_event(
        log: &alloy_primitives::Log,
    ) -> Result<alloy_primitives::Log<Logs::AnotherLog>, alloy_sol_types::Error> {
        Logs::AnotherLog::decode_log(log, true)
    }
}
