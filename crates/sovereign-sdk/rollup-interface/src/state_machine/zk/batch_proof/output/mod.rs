use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Genesis output module
pub mod v1;
/// Kumquat output module
pub mod v2;

/// State diff produced by the Zk proof
pub type CumulativeStateDiff = BTreeMap<Vec<u8>, Option<Vec<u8>>>;
