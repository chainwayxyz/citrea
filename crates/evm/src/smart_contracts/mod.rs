//! Includes the smart contracts used by the citrea-evm and the rollup itself, extensively for testing.

mod blockhash_contract;
mod caller_contract;
mod coinbase_contract;
mod hive_contract;
mod infinite_loop_contract;
mod logs_contract;
mod payable_contract;
mod self_destructor_contract;
mod simple_storage_contract;

pub use blockhash_contract::BlockHashContract;
pub use caller_contract::CallerContract;
pub use coinbase_contract::CoinbaseContract;
pub use hive_contract::HiveContract;
pub use infinite_loop_contract::InfiniteLoopContract;
pub use logs_contract::LogsContract;
pub use payable_contract::SimplePayableContract;
pub use self_destructor_contract::SelfDestructorContract;
pub use simple_storage_contract::SimpleStorageContract;

/// Trait for testing smart contracts.
pub trait TestContract: Default {
    /// Common method of all smart contracts. Returns bytecode
    fn byte_code(&self) -> Vec<u8>;
}
