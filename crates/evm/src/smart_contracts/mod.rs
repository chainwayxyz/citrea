//! Includes the smart contracts used by the citrea-evm and the rollup itself, extensively for testing.

mod blob_base_fee_contract;
mod blockhash_contract;
mod caller_contract;
mod coinbase_contract;
mod hive_contract;
mod infinite_loop_contract;
mod logs_contract;
mod mcopy_contract;
mod payable_contract;
mod self_destructor_contract;
mod selfdestructing_constructor;
mod simple_storage_contract;
mod transient_storage_contract;

pub use blob_base_fee_contract::BlobBaseFeeContract;
pub use blockhash_contract::BlockHashContract;
pub use caller_contract::CallerContract;
pub use coinbase_contract::CoinbaseContract;
pub use hive_contract::HiveContract;
pub use infinite_loop_contract::InfiniteLoopContract;
pub use logs_contract::{AnotherLogEvent, LogEvent, LogsContract};
pub use mcopy_contract::McopyContract;
pub use payable_contract::SimplePayableContract;
pub use self_destructor_contract::SelfDestructorContract;
pub use selfdestructing_constructor::SelfdestructingConstructorContract;
pub use simple_storage_contract::SimpleStorageContract;
pub use transient_storage_contract::TransientStorageContract;

/// Trait for testing smart contracts.
pub trait TestContract: Default {
    /// Common method of all smart contracts. Returns bytecode
    fn byte_code(&self) -> Vec<u8>;
}
