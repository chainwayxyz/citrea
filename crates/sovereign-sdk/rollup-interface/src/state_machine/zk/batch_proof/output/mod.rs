use std::collections::BTreeMap;

use crate::RefCount;

/// Genesis output module
pub mod v1;
/// Kumquat output module
pub mod v2;
/// Fork2 output module
pub mod v3;

/// State diff produced by the Zk proof
pub type CumulativeStateDiff = BTreeMap<RefCount<[u8]>, Option<RefCount<[u8]>>>;
