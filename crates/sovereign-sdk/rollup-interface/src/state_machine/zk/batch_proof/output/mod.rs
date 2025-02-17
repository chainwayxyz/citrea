use std::collections::BTreeMap;

/// Genesis output module
pub mod v1;
/// Kumquat output module
pub mod v2;
/// Fork2 output module
pub mod v3;

/// State diff produced by the Zk proof
pub type CumulativeStateDiff = BTreeMap<Vec<u8>, Option<Vec<u8>>>;
