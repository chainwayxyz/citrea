use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::Context;
use tokio::process::Command;
use tokio::time::{sleep, Duration, Instant};

use super::config::{config_to_file, RollupConfig, TestConfig};
use super::framework::TestContext;
use super::node::{L2Node, Node, SpawnOutput};
use super::utils::{get_citrea_path, get_stderr_path, get_stdout_path, retry};
use super::Result;
use crate::bitcoin_e2e::config::ProverConfig;
use crate::bitcoin_e2e::utils::get_genesis_path;
use crate::evm::make_test_client;
use crate::test_client::TestClient;
use crate::test_helpers::wait_for_prover_l1_height;

#[allow(unused)]
pub struct Prover {
    spawn_output: SpawnOutput,
    config: ProverConfig,
    rollup_config: RollupConfig,
    pub dir: PathBuf,
    pub client: Box<TestClient>,
}

impl Prover {
    pub async fn new(ctx: &TestContext) -> Result<Self> {
        let TestConfig {
            prover: prover_config,
            test_case,
            prover_rollup: rollup_config,
            ..
        } = &ctx.config;

        let dir = test_case.dir.join("prover");

        let spawn_output =
            Self::spawn(&(prover_config.clone(), rollup_config.clone()), &dir).await?;

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
            config: prover_config.to_owned(),
            dir,
            rollup_config: rollup_config.to_owned(),
            client,
        })
    }

    pub async fn wait_for_l1_height(&self, height: u64, timeout: Option<Duration>) {
        wait_for_prover_l1_height(&self.client, height, timeout).await
    }
}

impl Node for Prover {
    type Config = (ProverConfig, RollupConfig);
    type Client = TestClient;

    async fn spawn(config: &Self::Config, dir: &Path) -> Result<SpawnOutput> {
        let citrea = get_citrea_path();

        let stdout_file =
            File::create(get_stdout_path(dir)).context("Failed to create stdout file")?;
        let stderr_file =
            File::create(get_stderr_path(dir)).context("Failed to create stderr file")?;

        let (prover_config, rollup_config) = config;
        let config_path = dir.join("prover_config.toml");
        config_to_file(&prover_config, &config_path)?;

        let rollup_config_path = dir.join("prover_rollup_config.toml");
        config_to_file(&rollup_config, &rollup_config_path)?;

        Command::new(citrea)
            .arg("--da-layer")
            .arg("bitcoin")
            .arg("--rollup-config-path")
            .arg(rollup_config_path)
            .arg("--prover-config-path")
            .arg(config_path)
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
        anyhow::bail!("Prover failed to become ready within the specified timeout")
    }

    fn client(&self) -> &Self::Client {
        &self.client
    }
}

impl L2Node for Prover {}
