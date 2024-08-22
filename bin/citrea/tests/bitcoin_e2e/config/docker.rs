use std::path::PathBuf;

use super::{BitcoinConfig, RollupConfig};

pub struct DockerConfig {
    pub ports: Vec<u16>,
    pub image: String,
    pub cmd: Vec<String>,
    pub dir: PathBuf,
}

impl From<&BitcoinConfig> for DockerConfig {
    fn from(v: &BitcoinConfig) -> Self {
        let mut args = vec![
            "-regtest".to_string(),
            format!("-datadir=/bitcoin/data"),
            format!("-port={}", v.p2p_port),
            format!("-rpcport={}", v.rpc_port),
            format!("-rpcuser={}", v.rpc_user),
            format!("-rpcpassword={}", v.rpc_password),
            "-server".to_string(),
            "-rpcallowip=0.0.0.0/0".to_string(),
            "-rpcbind=0.0.0.0".to_string(),
        ];
        println!("Running bitcoind with args : {args:?}");

        args.extend(v.extra_args.iter().cloned());
        Self {
            ports: vec![v.rpc_port, v.p2p_port],
            image: v
                .docker_image
                .clone()
                .unwrap_or_else(|| "ruimarinho/bitcoin-core:latest".to_string()),
            cmd: args,
            dir: v.data_dir.clone(),
        }
    }
}

impl From<RollupConfig> for DockerConfig {
    fn from(value: RollupConfig) -> Self {
        todo!()
    }
}
