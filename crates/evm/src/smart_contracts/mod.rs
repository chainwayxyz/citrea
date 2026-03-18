//! Includes the smart contracts used by the citrea-evm and the rollup itself, extensively for testing.

mod blob_base_fee_contract;
mod blockhash_contract;
mod caller_contract;
mod coinbase_contract;
mod create2_factory_1a;
mod create2_factory_1b;
mod g1_add_contract;
mod hive_contract;
mod infinite_loop_contract;
mod kzg_point_evaluation_caller;
mod logs_contract;
mod mcopy_contract;
mod p256_verify_contract;
mod payable_contract;
mod schnorr_verify_contract;
mod self_destructor_contract;
mod selfdestruct_and_recreate;
mod selfdestructing_constructor;
mod simple_storage_contract;
mod simple_storage_duplicator_contract;
mod special_contract;
mod transient_storage_contract;

pub use blob_base_fee_contract::BlobBaseFeeContract;
pub use blockhash_contract::BlockHashContract;
pub use caller_contract::CallerContract;
pub use coinbase_contract::CoinbaseContract;
pub use create2_factory_1a::Create2Factory1aContract;
pub use create2_factory_1b::Create2Factory1bContract;
pub use g1_add_contract::G1AddCallerContract;
pub use hive_contract::HiveContract;
pub use infinite_loop_contract::InfiniteLoopContract;
pub use kzg_point_evaluation_caller::KZGPointEvaluationCallerContract;
pub use logs_contract::{AnotherLogEvent, LogEvent, LogsContract};
pub use mcopy_contract::McopyContract;
pub use p256_verify_contract::P256VerifyCallerContract;
pub use payable_contract::SimplePayableContract;
pub use schnorr_verify_contract::SchnorrVerifyCallerContract;
pub use self_destructor_contract::SelfDestructorContract;
pub use selfdestruct_and_recreate::SelfdestructAndRecreateContract;
pub use selfdestructing_constructor::SelfdestructingConstructorContract;
pub use simple_storage_contract::SimpleStorageContract;
pub use simple_storage_duplicator_contract::SimpleStorageDuplicatorContract;
pub use special_contract::SpecialContractContract;
pub use transient_storage_contract::TransientStorageContract;

/// Trait for testing smart contracts.
pub trait TestContract: Default {
    /// Common method of all smart contracts. Returns bytecode
    fn byte_code(&self) -> Vec<u8>;
}
