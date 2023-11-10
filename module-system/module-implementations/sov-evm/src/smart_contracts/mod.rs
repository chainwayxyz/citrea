use std::path::PathBuf;

mod logs_contract;
mod self_destructor_contract;
mod simple_storage_contract;
use ethers_contract::BaseContract;
use ethers_core::abi::Abi;
use ethers_core::types::Bytes;
pub use logs_contract::LogsContract;
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

pub trait TestContract {
    fn byte_code(&self) -> Bytes;
}
