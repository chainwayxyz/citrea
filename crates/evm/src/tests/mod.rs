use borsh::BorshDeserialize;
use sov_keys::default_signature::K256PublicKey;

mod call_tests;
mod ef_tests;
mod fork_tests;
mod genesis_tests;
mod hooks_tests;
mod queries;
mod sys_tx_tests;
pub(crate) mod test_signer;
mod tx_tests;
mod utils;

/// Chain ID used inside tests and default implementations.
/// Different chain ids can be given in the genesis config.
#[cfg(test)]
pub const DEFAULT_CHAIN_ID: u64 = 1;

fn get_test_seq_pub_key() -> K256PublicKey {
    K256PublicKey::try_from_slice(
        &hex::decode("036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f7").unwrap(),
    )
    .unwrap()
}
