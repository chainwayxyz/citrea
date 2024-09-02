use std::path::PathBuf;

use citrea_sequencer::SequencerConfig;

use super::rollup::RollupConfig;

#[derive(Clone, Debug)]
pub struct FullSequencerConfig {
    pub sequencer: SequencerConfig,
    pub rollup: RollupConfig,
    pub docker_image: Option<String>,
    pub dir: PathBuf,
}
