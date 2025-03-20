pub type L2BlockHash = [u8; 32];
pub use sov_rollup_interface::zk::Digest;

pub type SoftConfirmationHash = [u8; 32];
pub type BlockNumber = u64;
pub type L2Range = (BlockNumber, BlockNumber);
