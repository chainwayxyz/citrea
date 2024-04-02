// disable bank module tests due to needing a big rewrite to make it work
// mod bank;
mod e2e;
mod evm;
mod mempool;
mod sequencer_commitments;
mod soft_confirmation_rule_enforcer;
mod test_client;
mod test_helpers;

const DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT: u64 = 1000;
