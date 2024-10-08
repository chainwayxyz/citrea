mod bitcoin;
mod docker;
mod rollup;
mod test;
mod test_case;
mod utils;

use std::path::PathBuf;

pub use bitcoin::BitcoinConfig;
pub use docker::DockerConfig;
pub use node_configs::{ProverConfig, SequencerConfig};
pub use rollup::{default_rollup_config, RollupConfig};
pub use test::TestConfig;
pub use test_case::{TestCaseConfig, TestCaseEnv};
pub use utils::config_to_file;

#[derive(Clone, Debug)]
pub struct FullL2NodeConfig<T> {
    pub node: T,
    pub rollup: RollupConfig,
    pub docker_image: Option<String>,
    pub dir: PathBuf,
    pub env: Vec<(&'static str, &'static str)>,
}

pub type FullSequencerConfig = FullL2NodeConfig<SequencerConfig>;
pub type FullProverConfig = FullL2NodeConfig<ProverConfig>;
pub type FullFullNodeConfig = FullL2NodeConfig<()>;
