use anyhow::Context;
use citrea::NetworkArg;
use citrea_common::{
    from_toml_path, BatchProverConfig, FromEnv, LightClientProverConfig, NodeType, SequencerConfig,
};
use clap::{command, Parser};

#[derive(clap::ValueEnum, Clone, Debug)]
pub(crate) enum SupportedDaLayer {
    Mock,
    Bitcoin,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Args {
    /// The mode in which the node runs.
    /// This determines which guest code to use.
    /// Default is Mainnet.
    #[arg(short, long, default_value_t, value_enum)]
    pub(crate) network: NetworkArg,

    /// Run the development chain
    #[arg(long, default_value_t)]
    pub(crate) dev: bool,

    /// Run the regtest chain
    #[arg(long, default_value_t, conflicts_with = "dev")]
    pub(crate) dev_all_forks: bool,

    /// Path to the genesis configuration.
    /// Defines the genesis of module states like evm.
    #[arg(long)]
    pub(crate) genesis_paths: String,

    /// The data layer type.
    #[arg(long, default_value = "mock")]
    pub(crate) da_layer: SupportedDaLayer,

    /// The path to the rollup config, if a string is provided, it will be used as the path to the rollup config, otherwise environment variables will be used.
    #[arg(long)]
    pub(crate) rollup_config_path: Option<String>,

    /// The option to run the node in sequencer mode, if a string is provided, it will be used as the path to the sequencer config, otherwise environment variables will be used.
    #[arg(long, conflicts_with_all = ["batch_prover", "light_client_prover"])]
    pub(crate) sequencer: Option<Option<String>>,

    /// The option to run the node in batch prover mode, if a string is provided, it will be used as the path to the batch prover config, otherwise the environment variables will be used.
    #[arg(long, conflicts_with_all = ["sequencer", "light_client_prover"])]
    pub(crate) batch_prover: Option<Option<String>>,

    /// The option to run the node in light client prover mode, if a string is provided, it will be used as the path to the light client prover config, otherwise the environment variables will be used.
    #[arg(long, conflicts_with_all = ["sequencer", "batch_prover"])]
    pub(crate) light_client_prover: Option<Option<String>>,

    /// Logging verbosity
    #[arg(long, short = 'v', action = clap::ArgAction::Count, default_value = "0", env = "CITREA_VERBOSITY")]
    pub(crate) verbose: u8,
    /// Logging verbosity
    #[arg(long, short = 'q')]
    pub(crate) quiet: bool,
}

pub(crate) enum NodeWithConfig {
    Sequencer(SequencerConfig),
    FullNode,
    BatchProver(BatchProverConfig),
    LightClientProver(LightClientProverConfig),
}

impl std::fmt::Display for NodeWithConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let node_type: NodeType = self.into();
        node_type.fmt(f)
    }
}

impl From<&NodeWithConfig> for NodeType {
    fn from(value: &NodeWithConfig) -> Self {
        match value {
            NodeWithConfig::Sequencer(_) => NodeType::Sequencer,
            NodeWithConfig::FullNode => NodeType::FullNode,
            NodeWithConfig::BatchProver(_) => NodeType::BatchProver,
            NodeWithConfig::LightClientProver(_) => NodeType::LightClientProver,
        }
    }
}

pub(crate) fn node_type_from_args(args: &Args) -> anyhow::Result<NodeWithConfig> {
    let sequencer_config = match &args.sequencer {
        Some(Some(path)) => Some(
            from_toml_path(path)
                .context("Failed to read sequencer configuration from the config file")?,
        ),
        Some(None) => Some(
            SequencerConfig::from_env()
                .context("Failed to read sequencer configuration from the environment")?,
        ),
        None => None,
    };

    let batch_prover_config = match &args.batch_prover {
        Some(Some(path)) => Some(
            from_toml_path(path)
                .context("Failed to read prover configuration from the config file")?,
        ),
        Some(None) => Some(
            BatchProverConfig::from_env()
                .context("Failed to read prover configuration from the environment")?,
        ),
        None => None,
    };

    let light_client_prover_config = match &args.light_client_prover {
        Some(Some(path)) => Some(
            from_toml_path(path)
                .context("Failed to read prover configuration from the config file")?,
        ),
        Some(None) => Some(
            LightClientProverConfig::from_env()
                .context("Failed to read prover configuration from the environment")?,
        ),
        None => None,
    };

    if let Some(sequencer_config) = sequencer_config {
        return Ok(NodeWithConfig::Sequencer(sequencer_config));
    } else if let Some(batch_prover_config) = batch_prover_config {
        return Ok(NodeWithConfig::BatchProver(batch_prover_config));
    } else if let Some(light_client_prover_config) = light_client_prover_config {
        return Ok(NodeWithConfig::LightClientProver(
            light_client_prover_config,
        ));
    }
    Ok(NodeWithConfig::FullNode)
}
