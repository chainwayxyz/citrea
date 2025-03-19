use std::sync::Arc;

use bitcoin::Txid;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::error::{INTERNAL_ERROR_CODE, INTERNAL_ERROR_MSG};
use jsonrpsee::types::ErrorObjectOwned;
use serde::{Deserialize, Serialize};

use crate::fee::BumpFeeMethod;
use crate::monitoring::{MonitoredTx, TxStatus};
use crate::service::BitcoinService;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoredTxResponse {
    pub txid: Txid,
    pub vsize: usize,
    pub base_fee: Option<u64>,
    pub initial_broadcast: u64,
    pub initial_height: u64,
    pub prev_txid: Option<Txid>,
    pub next_txid: Option<Txid>,
    pub status: TxStatus,
    pub hex: String,
}

impl From<(Txid, MonitoredTx)> for MonitoredTxResponse {
    fn from((txid, tx): (Txid, MonitoredTx)) -> Self {
        let base_fee = if let TxStatus::Pending { base_fee, .. } = tx.status {
            Some(base_fee)
        } else {
            None
        };

        let raw_tx_bytes = bitcoin::consensus::encode::serialize(&tx.tx);
        let hex = hex::encode(&raw_tx_bytes);

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
        }
    }
}

#[rpc(client, server, namespace = "da")]
pub trait DaRpc {
    #[method(name = "getPendingTransactions")]
    async fn da_get_pending_transactions(&self) -> RpcResult<Vec<MonitoredTxResponse>>;

    #[method(name = "getMonitoredTransactions")]
    async fn da_get_monitored_transactions(&self) -> RpcResult<Vec<MonitoredTxResponse>>;

    #[method(name = "getTxStatus")]
    async fn da_get_tx_status(&self, txid: Txid) -> RpcResult<Option<TxStatus>>;

    #[method(name = "getLastMonitoredTx")]
    async fn da_get_last_monitored_tx(&self) -> RpcResult<Option<MonitoredTxResponse>>;

    #[method(name = "bumpFeeCpfp")]
    async fn da_bump_transaction_fee_cpfp(
        &self,
        txid: Option<Txid>,
        fee_rate: f64,
        force: Option<bool>,
    ) -> RpcResult<Txid>;

    #[method(name = "bumpFeeRbf")]
    async fn da_bump_transaction_fee_rbf(
        &self,
        txid: Option<Txid>,
        fee_rate: f64,
        force: Option<bool>,
    ) -> RpcResult<Txid>;
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
            .filter(|(_, tx)| matches!(tx.status, TxStatus::Pending { .. }))
            .map(Into::into)
            .collect::<Vec<_>>();

        Ok(txs)
    }

    async fn da_get_monitored_transactions(&self) -> RpcResult<Vec<MonitoredTxResponse>> {
        Ok(self
            .da
            .monitoring
            .get_monitored_txs()
            .await
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>())
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
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("{e}",)),
                )
            })
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
            .map_err(|e| {
                ErrorObjectOwned::owned(
                    INTERNAL_ERROR_CODE,
                    INTERNAL_ERROR_MSG,
                    Some(format!("{e}",)),
                )
            })
    }
}

pub struct DaRpcServerImpl {
    da: Arc<BitcoinService>,
}

impl DaRpcServerImpl {
    pub fn new(da: Arc<BitcoinService>) -> Self {
        Self { da }
    }
}

pub fn create_rpc_module(da: Arc<BitcoinService>) -> jsonrpsee::RpcModule<DaRpcServerImpl>
where
    DaRpcServerImpl: DaRpcServer,
{
    let server = DaRpcServerImpl::new(da);

    DaRpcServer::into_rpc(server)
}
