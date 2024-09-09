use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use async_trait::async_trait;
use bitcoin::Address;
use bitcoin_da::service::{get_relevant_blobs_from_txs, FINALITY_DEPTH};
use bitcoin_da::spec::blob::BlobWithSender;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use citrea_primitives::REVEAL_BATCH_PROOF_PREFIX;
use tokio::process::Command;
use tokio::time::sleep;

use super::config::BitcoinConfig;
use super::docker::DockerEnv;
use super::framework::TestContext;
use super::node::{LogProvider, Node, SpawnOutput};
use super::Result;
use crate::bitcoin_e2e::node::NodeKind;

pub struct BitcoinNode {
    spawn_output: SpawnOutput,
    pub config: BitcoinConfig,
    client: Client,
    gen_addr: Address,
}

impl BitcoinNode {
    pub async fn new(config: &BitcoinConfig, docker: &Option<DockerEnv>) -> Result<Self> {
        let spawn_output = match docker {
            Some(docker) => docker.spawn(config.into()).await?,
            None => Self::spawn(config)?,
        };

        let rpc_url = format!(
            "http://127.0.0.1:{}/wallet/{}",
            config.rpc_port,
            NodeKind::Bitcoin
        );
        let client = Client::new(
            &rpc_url,
            Auth::UserPass(config.rpc_user.clone(), config.rpc_password.clone()),
        )
        .await
        .context("Failed to create RPC client")?;

        wait_for_rpc_ready(&client, Duration::from_secs(60)).await?;
        println!("bitcoin RPC is ready");

        client
            .create_wallet(&NodeKind::Sequencer.to_string(), None, None, None, None)
            .await?;
        client
            .create_wallet(&NodeKind::Prover.to_string(), None, None, None, None)
            .await?;
        client
            .create_wallet(&NodeKind::Bitcoin.to_string(), None, None, None, None)
            .await?;

        let gen_addr = client
            .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))
            .await?
            .assume_checked();
        Ok(Self {
            spawn_output,
            config: config.clone(),
            client,
            gen_addr,
        })
    }

    pub async fn wait_mempool_len(
        &self,
        target_len: usize,
        timeout: Option<Duration>,
    ) -> Result<()> {
        let timeout = timeout.unwrap_or(Duration::from_secs(300));
        let start = Instant::now();
        while start.elapsed() < timeout {
            let mempool_len = self.get_raw_mempool().await?.len();
            if mempool_len >= target_len {
                return Ok(());
            }
            sleep(Duration::from_millis(500)).await;
        }
        bail!("Timeout waiting for mempool to reach length {}", target_len)
    }

    pub async fn fund_wallet(&self, name: String, blocks: u64) -> Result<()> {
        let rpc_url = format!("http://127.0.0.1:{}/wallet/{}", self.config.rpc_port, name);
        let client = Client::new(
            &rpc_url,
            Auth::UserPass(
                self.config.rpc_user.clone(),
                self.config.rpc_password.clone(),
            ),
        )
        .await
        .context("Failed to create RPC client")?;

        let gen_addr = client
            .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))
            .await?
            .assume_checked();
        client.generate_to_address(blocks, &gen_addr).await?;
        Ok(())
    }

    pub async fn get_finalized_height(&self) -> Result<u64> {
        Ok(self.get_block_count().await? - FINALITY_DEPTH + 1)
    }

    pub async fn get_relevant_blobs_from_block(&self, height: u64) -> Result<Vec<BlobWithSender>> {
        let hash = self.get_block_hash(height).await?;
        let block = self.get_block(&hash).await?;

        Ok(get_relevant_blobs_from_txs(
            block.txdata,
            REVEAL_BATCH_PROOF_PREFIX,
        ))
    }
}

#[async_trait]
impl RpcApi for BitcoinNode {
    async fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> bitcoincore_rpc::Result<T> {
        self.client.call(cmd, args).await
    }

    // Override deprecated generate method.
    // Uses node gen address and forward to `generate_to_address`
    async fn generate(
        &self,
        block_num: u64,
        _maxtries: Option<u64>,
    ) -> bitcoincore_rpc::Result<Vec<bitcoin::BlockHash>> {
        self.generate_to_address(block_num, &self.gen_addr).await
    }
}

impl Node for BitcoinNode {
    type Config = BitcoinConfig;
    type Client = Client;

    fn spawn(config: &Self::Config) -> Result<SpawnOutput> {
        let args = config.args();
        println!("Running bitcoind with args : {args:?}");

        Command::new("bitcoind")
            .args(&args)
            .kill_on_drop(true)
            .envs(config.env.clone())
            .spawn()
            .context("Failed to spawn bitcoind process")
            .map(SpawnOutput::Child)
    }

    fn spawn_output(&mut self) -> &mut SpawnOutput {
        &mut self.spawn_output
    }

    async fn wait_for_ready(&self, timeout: Duration) -> Result<()> {
        println!("Waiting for ready");
        let start = Instant::now();
        while start.elapsed() < timeout {
            if wait_for_rpc_ready(&self.client, timeout).await.is_ok() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        anyhow::bail!("Node failed to become ready within the specified timeout")
    }

    fn client(&self) -> &Self::Client {
        &self.client
    }

    fn env(&self) -> Vec<(&'static str, &'static str)> {
        self.config.env.clone()
    }
}

impl LogProvider for BitcoinNode {
    fn kind(&self) -> NodeKind {
        NodeKind::Bitcoin
    }

    fn log_path(&self) -> PathBuf {
        self.config.data_dir.join("regtest").join("debug.log")
    }
}

pub struct BitcoinNodeCluster {
    inner: Vec<BitcoinNode>,
}

impl BitcoinNodeCluster {
    pub async fn new(ctx: &TestContext) -> Result<Self> {
        let n_nodes = ctx.config.test_case.num_nodes;
        let mut cluster = Self {
            inner: Vec::with_capacity(n_nodes),
        };
        for config in ctx.config.bitcoin.iter() {
            let node = BitcoinNode::new(config, &ctx.docker).await?;
            cluster.inner.push(node)
        }

        Ok(cluster)
    }

    pub async fn stop_all(&mut self) -> Result<()> {
        for node in &mut self.inner {
            RpcApi::stop(node).await?;
            node.stop().await?;
        }
        Ok(())
    }

    pub async fn wait_for_sync(&self, timeout: Duration) -> Result<()> {
        let start = Instant::now();
        while start.elapsed() < timeout {
            let mut heights = HashSet::new();
            for node in &self.inner {
                let height = node.get_block_count().await?;
                println!("height : {height}");
                heights.insert(height);
            }

            if heights.len() == 1 {
                return Ok(());
            }

            sleep(Duration::from_secs(1)).await;
        }
        bail!("Nodes failed to sync within the specified timeout")
    }

    // Connect all bitcoin nodes between them
    pub async fn connect_nodes(&self) -> Result<()> {
        for (i, from_node) in self.inner.iter().enumerate() {
            for (j, to_node) in self.inner.iter().enumerate() {
                if i != j {
                    let ip = match &to_node.spawn_output {
                        SpawnOutput::Container(container) => container.ip.clone(),
                        _ => "127.0.0.1".to_string(),
                    };

                    let add_node_arg = format!("{}:{}", ip, to_node.config.p2p_port);
                    from_node.add_node(&add_node_arg).await?;
                }
            }
        }
        Ok(())
    }

    pub fn get(&self, index: usize) -> Option<&BitcoinNode> {
        self.inner.get(index)
    }

    #[allow(unused)]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut BitcoinNode> {
        self.inner.get_mut(index)
    }
}

async fn wait_for_rpc_ready(client: &Client, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        match client.get_blockchain_info().await {
            Ok(_) => return Ok(()),
            Err(_) => sleep(Duration::from_millis(500)).await,
        }
    }
    Err(anyhow::anyhow!("Timeout waiting for RPC to be ready"))
}
