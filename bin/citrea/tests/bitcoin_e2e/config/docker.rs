use super::{BitcoinConfig, FullSequencerConfig};
use crate::bitcoin_e2e::utils::get_genesis_path;

pub struct DockerConfig {
    pub ports: Vec<u16>,
    pub image: String,
    pub cmd: Vec<String>,
    pub dir: String,
}

impl From<&BitcoinConfig> for DockerConfig {
    fn from(v: &BitcoinConfig) -> Self {
        let mut args = v.args();

        // Docker specific args
        args.extend([
            "-datadir=/bitcoin/data".to_string(),
            "-rpcallowip=0.0.0.0/0".to_string(),
            "-rpcbind=0.0.0.0".to_string(),
            "-daemon=0".to_string(),
        ]);

        println!("Running bitcoind with args : {args:?}");
        Self {
            ports: vec![v.rpc_port, v.p2p_port],
            image: v
                .docker_image
                .clone()
                .unwrap_or_else(|| "bitcoin/bitcoin:latest".to_string()),
            cmd: args,
            dir: format!("{}:/bitcoin/data", v.data_dir.display()),
        }
    }
}

impl From<&FullSequencerConfig> for DockerConfig {
    fn from(v: &FullSequencerConfig) -> Self {
        let args = vec![
            "--da-layer".to_string(),
            "bitcoin".to_string(),
            "--rollup-config-path".to_string(),
            "sequencer_rollup_config.toml".to_string(),
            "--sequencer-config-path".to_string(),
            "sequencer_config.toml".to_string(),
            "--genesis-paths".to_string(),
            get_genesis_path(v.dir.parent().expect("Couldn't get parent dir"))
                .display()
                .to_string(),
        ];

        Self {
            ports: vec![v.rollup.rpc.bind_port],
            image: v
                .docker_image
                .clone()
                .unwrap_or_else(|| "citrea:latest".to_string()), // Default to local image
            cmd: args,
            dir: format!("{}:/sequencer/data", v.dir.display()),
        }
    }
}
