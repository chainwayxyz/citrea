// disable bank module tests due to needing a big rewrite to make it work
// mod bank;
mod e2e;

mod bitcoin_e2e;

mod evm;
mod mempool;
mod soft_confirmation_rule_enforcer;
mod test_client;
mod test_helpers;

const DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT: u64 = 1000;
const DEFAULT_PROOF_WAIT_DURATION: u64 = 600; // 10 minutes
const TEST_DATA_GENESIS_PATH: &str = "../../resources/test-data/integration-tests";
