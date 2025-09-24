//! Bitcoin RPC client wrapper with timeout protection

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bitcoincore_rpc::{Client, RpcApi};
use serde_json::Value;
use tokio::time::timeout;

/// Default timeout for RPC calls in seconds
const DEFAULT_RPC_TIMEOUT_SECONDS: u64 = 30;

/// A wrapper around bitcoincore_rpc::Client that adds timeout to all RPC calls
#[derive(Clone, Debug)]
pub struct BitcoinRpcClient {
    inner: Arc<Client>,
    timeout_duration: Duration,
}

impl BitcoinRpcClient {
    /// Create a new BitcoinRpcClient with the specified timeout
    pub fn new(client: Arc<Client>, timeout_seconds: Option<u64>) -> Self {
        let timeout_duration =
            Duration::from_secs(timeout_seconds.unwrap_or(DEFAULT_RPC_TIMEOUT_SECONDS));
        Self {
            inner: client,
            timeout_duration,
        }
    }

    /// Get inner client
    pub fn inner(&self) -> &Arc<Client> {
        &self.inner
    }
}

#[async_trait]
impl RpcApi for BitcoinRpcClient {
    async fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[Value],
    ) -> bitcoincore_rpc::Result<T> {
        timeout(self.timeout_duration, self.inner.call(cmd, args))
            .await
            .map_err(|_| {
                // Create an IO timeout error and convert it to bitcoincore_rpc Error
                let io_err = std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "RPC call '{}' timed out after {:?}",
                        cmd, self.timeout_duration
                    ),
                );
                bitcoincore_rpc::Error::Io(io_err)
            })?
    }
}
