use ethers_contract::BaseContract;
use ethers_core::types::Bytes;

use super::TestContract;
use super::{make_contract_from_abi, test_data_path};

/// Logs wrapper.
pub struct LogsContract {
    bytecode: Bytes,
    base_contract: BaseContract,
}

impl Default for LogsContract {
    fn default() -> Self {
        let contract_data = {
            let mut path = test_data_path();
            path.push("Logs.bin");

            let contract_data = std::fs::read_to_string(path).unwrap();
            hex::decode(contract_data).unwrap()
        };

        let contract = {
            let mut path = test_data_path();
            path.push("Logs.abi");

            make_contract_from_abi(path)
        };

        Self {
            bytecode: Bytes::from(contract_data),
            base_contract: contract,
        }
    }
}

impl TestContract for LogsContract {
    /// SimpleStorage bytecode.
    fn byte_code(&self) -> Bytes {
        self.bytecode.clone()
    }
}

impl LogsContract {
    /// Log publishing function of the smart contract.
    pub fn publish_event(&self, message: String) -> Bytes {
        self.base_contract.encode("publishEvent", message).unwrap()
    }
}
