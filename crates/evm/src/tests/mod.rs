mod call_tests;
mod cfg_tests;
mod genesis_tests;
mod hooks_tests;
mod queries;
mod sys_tx_tests;
pub(crate) mod test_signer;
mod tx_tests;

/// Chain ID used inside tests and default implementations.
/// Different chain ids can be given in the genesis config.
pub const DEFAULT_CHAIN_ID: u64 = 1;
