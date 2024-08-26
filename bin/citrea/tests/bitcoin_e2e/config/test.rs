use super::bitcoin::BitcoinConfig;
use super::rollup::RollupConfig;
use super::test_case::TestCaseConfig;
use super::FullSequencerConfig;
use sov_stf_runner::ProverConfig;

#[derive(Clone)]
pub struct TestConfig {
    pub test_case: TestCaseConfig,
    pub bitcoin: Vec<BitcoinConfig>,
    pub sequencer: FullSequencerConfig,
    pub prover: ProverConfig,
    pub prover_rollup: RollupConfig,
    pub full_node_rollup: RollupConfig,
}
