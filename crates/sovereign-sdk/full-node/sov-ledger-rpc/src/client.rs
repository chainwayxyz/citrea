//! A [`jsonrpsee`] client for interacting with the Sovereign SDK ledger
//! JSON-RPC API.
//!
//! See [`RpcClient`].

use jsonrpsee::proc_macros::rpc;
use sov_rollup_interface::rpc::{QueryMode, SoftConfirmationStatus};

use crate::HexHash;

/// A [`jsonrpsee`] trait for interacting with the ledger JSON-RPC API.
///
/// Client and server implementations are automatically generated by
/// [`jsonrpsee`], see [`RpcClient`] and [`RpcServer`].
///
/// For more information about the specific methods, see the
/// [`sov_rollup_interface::rpc`] module.
#[rpc(client, namespace = "ledger")]
pub trait Rpc<Slot, Batch, Tx>
where
    Slot: serde::Serialize,
    Batch: serde::Serialize,
    Tx: serde::Serialize,
{
    /// Gets a single transaction by hash.
    #[method(name = "getTransactionByHash")]
    async fn get_tx_by_hash(
        &self,
        hex_hash: HexHash,
        query_mode: QueryMode,
    ) -> RpcResult<Option<Tx>>;

    /// Gets a single event by number.
    #[method(name = "getSoftConfirmationStatus")]
    async fn get_soft_confirmation_status(
        &self,
        soft_batch_receipt: u64,
    ) -> RpcResult<SoftConfirmationStatus>;
}
