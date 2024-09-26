use super::bitcoin::BitcoinConfig;
use super::test_case::TestCaseConfig;
use super::{FullFullNodeConfig, FullProverConfig, FullSequencerConfig};

#[derive(Clone)]
pub struct TestConfig {
    pub test_case: TestCaseConfig,
    pub bitcoin: Vec<BitcoinConfig>,
    pub sequencer: FullSequencerConfig,
    pub prover: FullProverConfig,
    pub full_node: FullFullNodeConfig,
}
