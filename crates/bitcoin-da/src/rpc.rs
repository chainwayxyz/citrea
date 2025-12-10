//! Provides the RPC interface for the Bitcoin service in Citrea.
//! The namespace for these RPC methods is "da" (Data Availability).
//! This module defines methods to interact with monitored transactions,
//! including fetching, listing, and bumping fees for transactions.

use std::sync::Arc;

use bitcoin::consensus::Encodable;
use bitcoin::Txid;
use citrea_common::rpc::utils::internal_rpc_error;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};

use crate::fee::BumpFeeMethod;
use crate::monitoring::{MonitoredTx, MonitoredTxKind, TxStatus};
use crate::service::BitcoinService;

/// Response type for monitored transactions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MonitoredTxResponse {
    /// Txid.
    pub txid: Txid,
    /// Virtual size of the transaction.
    pub vsize: usize,
    /// Base fee for the transaction, if applicable.
    pub base_fee: Option<u64>,
    /// Initial broadcast time of the transaction.
    pub initial_broadcast: u64,
    /// Initial height at which the transaction was broadcast.
    pub initial_height: u64,
    /// Previous txid, if applicable.
    pub prev_txid: Option<Txid>,
    /// Next txid, if applicable.
    pub next_txid: Option<Txid>,
    /// Status of the transaction.
    pub status: TxStatus,
    /// Hex representation of the transaction, if requested.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    /// Transaction kind
    pub kind: MonitoredTxKind,
}

impl From<(Txid, MonitoredTx, bool)> for MonitoredTxResponse {
    fn from((txid, tx, with_hex): (Txid, MonitoredTx, bool)) -> Self {
        let base_fee = if let TxStatus::InMempool { base_fee, .. } = tx.status {
            Some(base_fee)
        } else {
            None
        };

        let hex = with_hex.then(|| {
            let mut buf = Vec::new();
            tx.tx
                .consensus_encode(&mut buf)
                .expect("Transaction encoding should not fail");
            hex::encode(&buf)
        });

        MonitoredTxResponse {
            txid,
            base_fee,
            vsize: tx.tx.vsize(),
            initial_broadcast: tx.initial_broadcast,
            initial_height: tx.initial_height,
            prev_txid: tx.prev_txid,
            next_txid: tx.next_txid,
            status: tx.status,
            hex,
            kind: tx.kind,
        }
    }
}

impl From<(Txid, MonitoredTx)> for MonitoredTxResponse {
    fn from((txid, tx): (Txid, MonitoredTx)) -> Self {
        Self::from((txid, tx, false)) // Defaults to hex verbosity false
    }
}

/// The interface for the Bitcoin service RPC methods.
#[rpc(client, server, namespace = "da")]
pub trait DaRpc {
    /// Retrieves all pending transactions that are being monitored.
    #[method(name = "getPendingTransactions")]
    async fn da_get_pending_transactions(&self) -> RpcResult<Vec<MonitoredTxResponse>>;

    /// Lists all monitored transactions, optionally including their hex representation.
    #[method(name = "listMonitoredTransactions")]
    async fn da_list_monitored_transactions(
        &self,
        with_hex: bool,
    ) -> RpcResult<Vec<MonitoredTxResponse>>;

    /// Retrieves a specific monitored transaction by its txid.
    #[method(name = "getMonitoredTransaction")]
    async fn da_get_monitored_transaction(
        &self,
        txid: Txid,
        with_hex: bool,
    ) -> RpcResult<Option<MonitoredTxResponse>>;

    /// Retrieves the status of a specific transaction by its txid.
    #[method(name = "getTxStatus")]
    async fn da_get_tx_status(&self, txid: Txid) -> RpcResult<Option<TxStatus>>;

    /// Retrieves the last monitored transaction, if any.
    #[method(name = "getLastMonitoredTx")]
    async fn da_get_last_monitored_tx(&self) -> RpcResult<Option<MonitoredTxResponse>>;

    /// Bumps the transaction fee using Child-Pays-For-Parent (CPFP) method.
    #[method(name = "bumpFeeCpfp")]
    async fn da_bump_transaction_fee_cpfp(
        &self,
        txid: Option<Txid>,
        fee_rate: f64,
        force: Option<bool>,
    ) -> RpcResult<Txid>;

    /// Bumps the transaction fee using Replace-By-Fee (RBF) method.
    #[method(name = "bumpFeeRbf")]
    async fn da_bump_transaction_fee_rbf(
        &self,
        txid: Option<Txid>,
        fee_rate: f64,
        force: Option<bool>,
    ) -> RpcResult<Txid>;
}

/// The implementation of the RPC itself.
pub struct DaRpcServerImpl {
    da: Arc<BitcoinService>,
}

#[async_trait::async_trait]
impl DaRpcServer for DaRpcServerImpl {
    async fn da_get_pending_transactions(&self) -> RpcResult<Vec<MonitoredTxResponse>> {
        let txs = self
            .da
            .monitoring
            .get_monitored_txs()
            .await
            .into_iter()
            .filter(|(_, tx)| matches!(tx.status, TxStatus::InMempool { .. }))
            .map(Into::into)
            .collect::<Vec<_>>();

        Ok(txs)
    }

    async fn da_list_monitored_transactions(
        &self,
        with_hex: bool,
    ) -> RpcResult<Vec<MonitoredTxResponse>> {
        Ok(self
            .da
            .monitoring
            .get_monitored_txs()
            .await
            .into_iter()
            .map(|(txid, tx)| (txid, tx, with_hex).into())
            .collect::<Vec<_>>())
    }

    async fn da_get_monitored_transaction(
        &self,
        txid: Txid,
        with_hex: bool,
    ) -> RpcResult<Option<MonitoredTxResponse>> {
        Ok(self
            .da
            .monitoring
            .get_monitored_tx(&txid)
            .await
            .map(|tx| (txid, tx, with_hex).into()))
    }

    async fn da_get_tx_status(&self, txid: Txid) -> RpcResult<Option<TxStatus>> {
        Ok(self.da.monitoring.get_tx_status(&txid).await)
    }

    async fn da_get_last_monitored_tx(&self) -> RpcResult<Option<MonitoredTxResponse>> {
        Ok(self.da.monitoring.get_last_tx().await.map(Into::into))
    }

    async fn da_bump_transaction_fee_cpfp(
        &self,
        txid: Option<Txid>,
        fee_rate: f64,
        force: Option<bool>,
    ) -> RpcResult<Txid> {
        self.da
            .bump_fee(txid, fee_rate, force, BumpFeeMethod::Cpfp)
            .await
            .map_err(internal_rpc_error)
    }

    async fn da_bump_transaction_fee_rbf(
        &self,
        txid: Option<Txid>,
        fee_rate: f64,
        force: Option<bool>,
    ) -> RpcResult<Txid> {
        self.da
            .bump_fee(txid, fee_rate, force, BumpFeeMethod::Rbf)
            .await
            .map_err(internal_rpc_error)
    }
}

/// Creates a new RPC module for the Bitcoin service.
pub fn create_rpc_module(da: Arc<BitcoinService>) -> jsonrpsee::RpcModule<DaRpcServerImpl>
where
    DaRpcServerImpl: DaRpcServer,
{
    let server = DaRpcServerImpl { da };

    DaRpcServer::into_rpc(server)
}
