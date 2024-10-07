use std::path::PathBuf;

use super::{BitcoinConfig, FullSequencerConfig};
use crate::bitcoin_e2e::utils::get_genesis_path;

#[derive(Debug)]
pub struct VolumeConfig {
    pub name: String,
    pub target: String,
}

#[derive(Debug)]
pub struct DockerConfig {
    pub ports: Vec<u16>,
    pub image: String,
    pub cmd: Vec<String>,
    pub log_path: PathBuf,
    pub volume: VolumeConfig,
}

impl From<&BitcoinConfig> for DockerConfig {
    fn from(v: &BitcoinConfig) -> Self {
        let mut args = v.args();

        // Docker specific args
        args.extend([
            "-rpcallowip=0.0.0.0/0".to_string(),
            "-rpcbind=0.0.0.0".to_string(),
            "-daemonwait=0".to_string(),
        ]);

        Self {
            ports: vec![v.rpc_port, v.p2p_port],
            image: v
                .docker_image
                .clone()
                .unwrap_or_else(|| "bitcoin/bitcoin:27.1-alpine".to_string()),
            cmd: args,
            log_path: v.data_dir.join("regtest").join("debug.log"),
            volume: VolumeConfig {
                name: format!("bitcoin-{}", v.idx),
                target: "/home/bitcoin/.bitcoin".to_string(),
            },
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
            log_path: v.dir.join("stdout"),
            volume: VolumeConfig {
                name: "sequencer".to_string(),
                target: "/sequencer/data".to_string(),
            },
        }
    }
}
