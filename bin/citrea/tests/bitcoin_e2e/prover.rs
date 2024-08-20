use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::Context;
use tokio::process::{Child, Command};
use tokio::time::{sleep, Duration, Instant};

use super::config::config_to_file;
use super::config::RollupConfig;
use super::config::TestConfig;
use super::node::Node;
use super::utils::{get_citrea_path, get_stderr_path, get_stdout_path};
use super::Result;
use crate::bitcoin_e2e::config::ProverConfig;
use crate::bitcoin_e2e::utils::get_genesis_path;
use crate::evm::make_test_client;
use crate::test_client::TestClient;

#[allow(unused)]
pub struct Prover {
    process: Child,
    config: ProverConfig,
    rollup_config: RollupConfig,
    pub dir: PathBuf,
    pub client: Box<TestClient>,
}

impl Prover {
    pub async fn new(config: &TestConfig) -> Result<Self> {
        let TestConfig {
            prover: prover_config,
            test_case,
            prover_rollup: rollup_config,
            ..
        } = config;

        let dir = test_case.dir.join("prover");

        println!("Prover config: {prover_config:#?}");
        println!("Rollup config: {rollup_config:#?}");
        println!("Prover dir: {:#?}", dir);

        let process =
            Self::spawn(&(config.prover.clone(), config.prover_rollup.clone()), &dir).await?;

        // Wait for ws server
        // TODO Add to wait_for_ready
        sleep(Duration::from_secs(3)).await;

        let socket_addr = SocketAddr::new(
            rollup_config
                .rpc
                .bind_host
                .parse()
                .context("Failed to parse bind host")?,
            rollup_config.rpc.bind_port,
        );
        let client = make_test_client(socket_addr).await;

        Ok(Self {
            process,
            config: prover_config.to_owned(),
            dir,
            rollup_config: rollup_config.to_owned(),
            client,
        })
    }
}

impl Node for Prover {
    type Config = (ProverConfig, RollupConfig);

    async fn spawn(config: &Self::Config, dir: &Path) -> Result<Child> {
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
            .arg(get_genesis_path())
            .stdout(Stdio::from(stdout_file))
            .stderr(Stdio::from(stderr_file))
            .kill_on_drop(true)
            .spawn()
            .context("Failed to spawn citrea process")
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(self.process.kill().await?)
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
}
