use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;

use anyhow::Context;
use tokio::process::Command;
use tokio::time::{sleep, Duration, Instant};

use super::config::{config_to_file, FullSequencerConfig, TestConfig};
use super::framework::TestContext;
use super::node::{LogProvider, Node, NodeKind, SpawnOutput};
use super::utils::{get_citrea_path, get_stderr_path, get_stdout_path, retry};
use super::Result;
use crate::bitcoin_e2e::utils::get_genesis_path;
use crate::evm::make_test_client;
use crate::test_client::TestClient;

#[allow(unused)]
pub struct Sequencer {
    spawn_output: SpawnOutput,
    config: FullSequencerConfig,
    pub client: Box<TestClient>,
}

impl Sequencer {
    pub async fn new(ctx: &TestContext) -> Result<Self> {
        let TestConfig {
            sequencer: config, ..
        } = &ctx.config;

        let spawn_output = Self::spawn(config)?;

        let socket_addr = SocketAddr::new(
            config
                .rollup
                .rpc
                .bind_host
                .parse()
                .context("Failed to parse bind host")?,
            config.rollup.rpc.bind_port,
        );

        let client = retry(|| async { make_test_client(socket_addr).await }, None).await?;

        Ok(Self {
            spawn_output,
            config: config.clone(),
            client,
        })
    }

    pub fn dir(&self) -> &PathBuf {
        &self.config.dir
    }

    pub fn min_soft_confirmations_per_commitment(&self) -> u64 {
        self.config.node.min_soft_confirmations_per_commitment
    }
}

impl Node for Sequencer {
    type Config = FullSequencerConfig;
    type Client = TestClient;

    fn spawn(config: &Self::Config) -> Result<SpawnOutput> {
        let citrea = get_citrea_path();
        let dir = &config.dir;

        let stdout_file =
            File::create(get_stdout_path(dir)).context("Failed to create stdout file")?;
        let stderr_file =
            File::create(get_stderr_path(dir)).context("Failed to create stderr file")?;

        let config_path = dir.join("sequencer_config.toml");
        config_to_file(&config.node, &config_path)?;

        let rollup_config_path = dir.join("sequencer_rollup_config.toml");
        config_to_file(&config.rollup, &rollup_config_path)?;

        Command::new(citrea)
            .arg("--da-layer")
            .arg("bitcoin")
            .arg("--rollup-config-path")
            .arg(rollup_config_path)
            .arg("--sequencer-config-path")
            .arg(config_path)
            .arg("--genesis-paths")
            .arg(get_genesis_path(
                dir.parent().expect("Couldn't get parent dir"),
            ))
            .envs(config.env.clone())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .kill_on_drop(true)
            .spawn()
            .context("Failed to spawn citrea process")
            .map(SpawnOutput::Child)
    }

    fn spawn_output(&mut self) -> &mut SpawnOutput {
        &mut self.spawn_output
    }

    async fn wait_for_ready(&self, timeout: Option<Duration>) -> Result<()> {
        let start = Instant::now();
        let timeout = timeout.unwrap_or(Duration::from_secs(30));
        while start.elapsed() < timeout {
            if self
                .client
                .ledger_get_head_soft_confirmation()
                .await
                .is_ok()
            {
                return Ok(());
            }
            sleep(Duration::from_millis(500)).await;
        }
        anyhow::bail!("Sequencer failed to become ready within the specified timeout")
    }

    fn client(&self) -> &Self::Client {
        &self.client
    }

    fn env(&self) -> Vec<(&'static str, &'static str)> {
        self.config.env.clone()
    }
}

impl LogProvider for Sequencer {
    fn kind(&self) -> NodeKind {
        NodeKind::Sequencer
    }

    fn log_path(&self) -> PathBuf {
        get_stdout_path(self.dir())
    }
}
