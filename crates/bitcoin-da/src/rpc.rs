//! Provides the RPC interface for the Bitcoin service in Citrea.
//! The namespace for these RPC methods is "da" (Data Availability).
//! This module defines methods to interact with monitored transactions,
//! including fetching and listing monitored transactions.

use std::sync::Arc;

use bitcoin::consensus::Encodable;
use bitcoin::{Transaction, Txid};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};

use crate::helpers::parsers::parse_relevant_transaction;
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
    pub base_fee: Option<f64>,
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

fn tx_sender_monitored_tx_kind(tx: &Transaction) -> MonitoredTxKind {
    if parse_relevant_transaction(tx).is_ok() {
        MonitoredTxKind::Reveal
    } else {
        MonitoredTxKind::Commit
    }
}

fn tx_sender_response(
    txid: Txid,
    tx: &Transaction,
    status: TxStatus,
    with_hex: bool,
) -> MonitoredTxResponse {
    let base_fee = if let TxStatus::InMempool { base_fee, .. } = status {
        Some(base_fee)
    } else {
        None
    };

    let hex = with_hex.then(|| {
        let mut buf = Vec::new();
        tx.consensus_encode(&mut buf)
            .expect("Transaction encoding should not fail");
        hex::encode(&buf)
    });

    MonitoredTxResponse {
        txid,
        vsize: tx.vsize(),
        base_fee,
        initial_broadcast: 0,
        initial_height: 0,
        prev_txid: None,
        next_txid: None,
        status,
        hex,
        kind: tx_sender_monitored_tx_kind(tx),
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
}

/// The implementation of the RPC itself.
pub struct DaRpcServerImpl {
    da: Arc<BitcoinService>,
}

#[async_trait::async_trait]
impl DaRpcServer for DaRpcServerImpl {
    async fn da_get_pending_transactions(&self) -> RpcResult<Vec<MonitoredTxResponse>> {
        if self.da.uses_tx_sender() {
            let mut txs = Vec::new();
            for tx in self.da.get_pending_monitored_transactions().await {
                let txid = tx.compute_txid();
                let Some(status) = self.da.get_monitored_tx_status(txid).await else {
                    continue;
                };
                txs.push(tx_sender_response(txid, &tx, status, false));
            }

            return Ok(txs);
        }

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
        if self.da.uses_tx_sender() {
            let mut txs = Vec::new();
            for tx in self.da.get_pending_monitored_transactions().await {
                let txid = tx.compute_txid();
                let Some(status) = self.da.get_monitored_tx_status(txid).await else {
                    continue;
                };
                txs.push(tx_sender_response(txid, &tx, status, with_hex));
            }

            return Ok(txs);
        }

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
        if self.da.uses_tx_sender() {
            let Some(tx) = self.da.get_transaction(&txid).await else {
                return Ok(None);
            };
            let Some(status) = self.da.get_monitored_tx_status(txid).await else {
                return Ok(None);
            };

            return Ok(Some(tx_sender_response(txid, &tx, status, with_hex)));
        }

        Ok(self
            .da
            .monitoring
            .get_monitored_tx(&txid)
            .await
            .map(|tx| (txid, tx, with_hex).into()))
    }

    async fn da_get_tx_status(&self, txid: Txid) -> RpcResult<Option<TxStatus>> {
        Ok(self.da.get_monitored_tx_status(txid).await)
    }

    async fn da_get_last_monitored_tx(&self) -> RpcResult<Option<MonitoredTxResponse>> {
        if self.da.uses_tx_sender() {
            let last = self.da.get_pending_monitored_transactions().await.pop();
            let Some(tx) = last else {
                return Ok(None);
            };
            let txid = tx.compute_txid();
            let Some(status) = self.da.get_monitored_tx_status(txid).await else {
                return Ok(None);
            };

            return Ok(Some(tx_sender_response(txid, &tx, status, false)));
        }

        Ok(self.da.monitoring.get_last_tx().await.map(Into::into))
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
