use citrea_sequencer::SequencerConfig;
use sov_stf_runner::ProverConfig;

use super::bitcoin::BitcoinConfig;
use super::rollup::RollupConfig;
use super::test_case::TestCaseConfig;

#[derive(Clone)]
pub struct TestConfig {
    pub test_case: TestCaseConfig,
    pub bitcoin: Vec<BitcoinConfig>,
    pub sequencer: SequencerConfig,
    pub sequencer_rollup: RollupConfig,
    pub prover: ProverConfig,
    pub prover_rollup: RollupConfig,
    pub full_node_rollup: RollupConfig,
}
