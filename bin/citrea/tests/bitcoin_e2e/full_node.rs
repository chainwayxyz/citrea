use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{bail, Context};
use sov_rollup_interface::rpc::{SequencerCommitmentResponse, VerifiedProofResponse};
use tokio::process::Command;
use tokio::time::{sleep, Duration, Instant};

use super::config::{config_to_file, FullFullNodeConfig, TestConfig};
use super::framework::TestContext;
use super::node::{LogProvider, Node, NodeKind, SpawnOutput};
use super::utils::{get_citrea_path, get_stderr_path, get_stdout_path, retry};
use super::Result;
use crate::bitcoin_e2e::utils::get_genesis_path;
use crate::evm::make_test_client;
use crate::test_client::TestClient;

#[allow(unused)]
pub struct FullNode {
    spawn_output: SpawnOutput,
    config: FullFullNodeConfig,
    pub client: Box<TestClient>,
}

impl FullNode {
    pub async fn new(ctx: &TestContext) -> Result<Self> {
        let TestConfig {
            full_node: full_node_config,
            ..
        } = &ctx.config;

        let spawn_output = Self::spawn(full_node_config)?;

        let socket_addr = SocketAddr::new(
            full_node_config
                .rollup
                .rpc
                .bind_host
                .parse()
                .context("Failed to parse bind host")?,
            full_node_config.rollup.rpc.bind_port,
        );
        let client = retry(|| async { make_test_client(socket_addr).await }, None).await?;

        Ok(Self {
            spawn_output,
            config: full_node_config.clone(),
            client,
        })
    }

    pub async fn wait_for_sequencer_commitments(
        &self,
        height: u64,
        timeout: Option<Duration>,
    ) -> Result<Vec<SequencerCommitmentResponse>> {
        let start = Instant::now();
        let timeout = timeout.unwrap_or(Duration::from_secs(30));

        loop {
            if start.elapsed() >= timeout {
                bail!("FullNode failed to get sequencer commitments within the specified timeout");
            }

            match self
                .client
                .ledger_get_sequencer_commitments_on_slot_by_number(height)
                .await
            {
                Ok(Some(commitments)) => return Ok(commitments),
                Ok(None) => sleep(Duration::from_millis(500)).await,
                Err(e) => bail!("Error fetching sequencer commitments: {}", e),
            }
        }
    }

    pub async fn wait_for_zkproofs(
        &self,
        height: u64,
        timeout: Option<Duration>,
    ) -> Result<Vec<VerifiedProofResponse>> {
        let start = Instant::now();
        let timeout = timeout.unwrap_or(Duration::from_secs(30));

        loop {
            if start.elapsed() >= timeout {
                bail!("FullNode failed to get zkproofs within the specified timeout");
            }

            match self
                .client
                .ledger_get_verified_proofs_by_slot_height(height)
                .await
            {
                Some(proofs) => return Ok(proofs),
                None => sleep(Duration::from_millis(500)).await,
            }
        }
    }
}

impl Node for FullNode {
    type Config = FullFullNodeConfig;
    type Client = TestClient;

    fn spawn(config: &Self::Config) -> Result<SpawnOutput> {
        let citrea = get_citrea_path();
        let dir = &config.dir;

        let stdout_file =
            File::create(get_stdout_path(dir)).context("Failed to create stdout file")?;
        let stderr_file =
            File::create(get_stderr_path(dir)).context("Failed to create stderr file")?;

        let rollup_config_path = dir.join("full_node_rollup_config.toml");
        config_to_file(&config.rollup, &rollup_config_path)?;

        Command::new(citrea)
            .arg("--da-layer")
            .arg("bitcoin")
            .arg("--rollup-config-path")
            .arg(rollup_config_path)
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
        bail!("FullNode failed to become ready within the specified timeout")
    }

    fn client(&self) -> &Self::Client {
        &self.client
    }

    fn env(&self) -> Vec<(&'static str, &'static str)> {
        self.config.env.clone()
    }

    fn config_mut(&mut self) -> &mut Self::Config {
        &mut self.config
    }
}

impl LogProvider for FullNode {
    fn kind(&self) -> NodeKind {
        NodeKind::FullNode
    }

    fn log_path(&self) -> PathBuf {
        get_stdout_path(&self.config.dir)
    }
}
