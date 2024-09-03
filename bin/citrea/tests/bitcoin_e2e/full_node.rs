use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{bail, Context};
use sov_rollup_interface::rpc::SequencerCommitmentResponse;
use tokio::process::Command;
use tokio::time::{sleep, Duration, Instant};

use super::config::{config_to_file, TestConfig};
use super::framework::TestContext;
use super::node::{L2Node, Node, SpawnOutput};
use super::utils::{get_citrea_path, get_stderr_path, get_stdout_path, retry};
use super::Result;
use crate::bitcoin_e2e::config::RollupConfig;
use crate::bitcoin_e2e::utils::get_genesis_path;
use crate::evm::make_test_client;
use crate::test_client::TestClient;

#[allow(unused)]
pub struct FullNode {
    spawn_output: SpawnOutput,
    config: RollupConfig,
    pub dir: PathBuf,
    pub client: Box<TestClient>,
}

impl FullNode {
    pub async fn new(ctx: &TestContext) -> Result<Self> {
        let TestConfig {
            test_case,
            full_node_rollup: rollup_config,
            ..
        } = &ctx.config;

        let dir = test_case.dir.join("full-node");

        let spawn_output = Self::spawn(rollup_config, &dir).await?;

        let socket_addr = SocketAddr::new(
            rollup_config
                .rpc
                .bind_host
                .parse()
                .context("Failed to parse bind host")?,
            rollup_config.rpc.bind_port,
        );
        let client = retry(|| async { make_test_client(socket_addr).await }, None).await?;

        Ok(Self {
            spawn_output,
            config: rollup_config.clone(),
            dir,
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
}

impl Node for FullNode {
    type Config = RollupConfig;
    type Client = TestClient;

    async fn spawn(config: &Self::Config, dir: &Path) -> Result<SpawnOutput> {
        let citrea = get_citrea_path();

        let stdout_file =
            File::create(get_stdout_path(dir)).context("Failed to create stdout file")?;
        let stderr_file =
            File::create(get_stderr_path(dir)).context("Failed to create stderr file")?;

        let rollup_config_path = dir.join("full_node_rollup_config.toml");
        config_to_file(&config, &rollup_config_path)?;

        Command::new(citrea)
            .arg("--da-layer")
            .arg("bitcoin")
            .arg("--rollup-config-path")
            .arg(rollup_config_path)
            .arg("--genesis-paths")
            .arg(get_genesis_path(
                dir.parent().expect("Couldn't get parent dir"),
            ))
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

    async fn wait_for_ready(&self, timeout: Duration) -> Result<()> {
        let start = Instant::now();
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
}

impl L2Node for FullNode {}
