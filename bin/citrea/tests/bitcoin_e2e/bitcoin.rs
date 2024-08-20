use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use async_trait::async_trait;
use bitcoin::Address;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use tokio::process::{Child, Command};
use tokio::time::sleep;

use super::config::BitcoinConfig;
use super::config::TestConfig;
use super::node::Node;
use super::Result;

pub struct BitcoinNode {
    process: Child,
    pub config: BitcoinConfig,
    client: Client,
    gen_addr: Address,
}

impl BitcoinNode {
    pub async fn new(config: &BitcoinConfig) -> Result<Self> {
        let process = Self::spawn(config, &PathBuf::default()).await?;

        let rpc_url = format!("http://127.0.0.1:{}", config.rpc_port);
        let client = Client::new(
            &rpc_url,
            Auth::UserPass(config.rpc_user.clone(), config.rpc_password.clone()),
        )
        .await
        .context("Failed to create RPC client")?;

        wait_for_rpc_ready(&client, Duration::from_secs(30)).await?;
        println!("bitcoin RPC is ready");

        client
            .create_wallet("wallet", None, None, None, None)
            .await?;

        let gen_addr = client.get_new_address(None, None).await?.assume_checked();
        Ok(Self {
            process,
            config: config.clone(),
            client,
            gen_addr,
        })
    }

    pub fn get_log_path(&self) -> PathBuf {
        self.config
            .data_dir
            .as_ref()
            .unwrap()
            .join("regtest")
            .join("debug.log")
    }

    pub async fn wait_mempool_len(
        &self,
        target_len: usize,
        timeout: Option<Duration>,
    ) -> Result<()> {
        let timeout = timeout.unwrap_or(Duration::from_secs(60));
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

    async fn spawn(config: &Self::Config, _dir: &Path) -> Result<Child> {
        let mut args = vec![
            "-regtest".to_string(),
            format!("-datadir={}", config.data_dir.as_ref().unwrap().display()),
            format!("-port={}", config.p2p_port),
            format!("-rpcport={}", config.rpc_port),
            format!("-rpcuser={}", config.rpc_user),
            format!("-rpcpassword={}", config.rpc_password),
            "-server".to_string(),
            "-daemon".to_string(),
        ];
        println!("Running bitcoind with args : {args:?}");

        args.extend(config.extra_args.iter().cloned());

        Command::new("bitcoind")
            .args(&args)
            .spawn()
            .context("Failed to spawn bitcoind process")
    }

    async fn stop(&mut self) -> Result<()> {
        RpcApi::stop(self).await?;
        Ok(self.process.kill().await?)
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
}

pub struct NodeCluster {
    inner: Vec<BitcoinNode>,
}

impl NodeCluster {
    pub async fn new(config: &TestConfig) -> Result<Self> {
        let n_nodes = config.test_case.num_nodes;
        let mut cluster = Self {
            inner: Vec::with_capacity(n_nodes),
        };
        for config in config.bitcoin.iter() {
            let node = BitcoinNode::new(config).await?;
            cluster.inner.push(node)
        }

        Ok(cluster)
    }

    pub async fn stop_all(&mut self) -> Result<()> {
        for node in &mut self.inner {
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
                heights.insert(height);
            }

            if heights.len() == 1 {
                return Ok(());
            }

            sleep(Duration::from_secs(1)).await;
        }
        bail!("Nodes failed to sync within the specified timeout")
    }

    // Connect all nodes between them
    pub async fn connect_nodes(&self) -> Result<()> {
        for (i, from_node) in self.inner.iter().enumerate() {
            for (j, to_node) in self.inner.iter().enumerate() {
                if i != j {
                    let add_node_arg = format!("127.0.0.1:{}", to_node.config.p2p_port);
                    from_node.add_node(&add_node_arg).await?;
                }
            }
        }
        Ok(())
    }

    pub fn get(&self, index: usize) -> Option<&BitcoinNode> {
        self.inner.get(index)
    }

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
