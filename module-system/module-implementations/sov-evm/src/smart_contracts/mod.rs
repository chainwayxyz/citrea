use std::any::Any;
use std::path::PathBuf;

mod blockhash_contract;
mod caller_contract;
mod coinbase_contract;
mod logs_contract;
mod payable_contract;
mod self_destructor_contract;
mod simple_storage_contract;

pub use blockhash_contract::BlockHashContract;
pub use caller_contract::CallerContract;
pub use coinbase_contract::CoinbaseContract;
use ethers_contract::BaseContract;
use ethers_core::abi::Abi;
use ethers_core::types::Bytes;
pub use logs_contract::LogsContract;
pub use payable_contract::SimplePayableContract;
pub use self_destructor_contract::SelfDestructorContract;
pub use simple_storage_contract::SimpleStorageContract;

fn test_data_path() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("src");
    path.push("evm");
    path.push("test_data");
    path
}

fn make_contract_from_abi(path: PathBuf) -> BaseContract {
    let abi_json = std::fs::read_to_string(path).unwrap();
    let abi: Abi = serde_json::from_str(&abi_json).unwrap();
    BaseContract::from(abi)
}

/// Trait for testing smart contracts.
pub trait TestContract {
    /// Common method of all smart contracts. Returns bytecode
    fn byte_code(&self) -> Bytes;
    /// Dynamically dispatch from trait.
    fn as_any(&self) -> &dyn Any;
    /// Create the default instance of the smart contract.
    fn default_(&self) -> Self
    where
        Self: Sized;
}
