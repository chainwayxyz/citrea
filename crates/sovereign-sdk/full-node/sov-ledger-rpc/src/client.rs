//! A [`jsonrpsee`] client for interacting with the Sovereign SDK ledger
//! JSON-RPC API.
//!
//! See [`RpcClient`].

use jsonrpsee::proc_macros::rpc;
use sov_rollup_interface::rpc::{
    BatchIdentifier, EventIdentifier, QueryMode, SlotIdentifier, SoftConfirmationStatus,
    TxIdentifier,
};
use sov_rollup_interface::stf::Event;

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
    /// Gets the latest slot in the ledger.
    #[method(name = "getHead")]
    async fn get_head(&self, query_mode: QueryMode) -> RpcResult<Option<Slot>>;

    /// Gets a list of slots by ID. The IDs need not be ordered.
    #[method(name = "getSlots")]
    async fn get_slots(
        &self,
        slot_ids: Vec<SlotIdentifier>,
        query_mode: QueryMode,
    ) -> RpcResult<Vec<Option<Slot>>>;

    /// Gets a list of batches by ID. The IDs need not be ordered.
    #[method(name = "getBatches")]
    async fn get_batches(
        &self,
        batch_ids: Vec<BatchIdentifier>,
        query_mode: QueryMode,
    ) -> RpcResult<Vec<Option<Batch>>>;

    /// Gets a list of transactions by ID. The IDs need not be ordered.
    #[method(name = "getTransactions")]
    async fn get_transactions(
        &self,
        transaction_ids: Vec<TxIdentifier>,
        query_mode: QueryMode,
    ) -> RpcResult<Vec<Option<Tx>>>;

    /// Gets a list of events by ID. The IDs need not be ordered.
    #[method(name = "getEvents")]
    async fn get_events(&self, event_ids: Vec<EventIdentifier>) -> RpcResult<Vec<Option<Event>>>;

    /// Gets a single slot by hash.
    #[method(name = "getSlotByHash")]
    async fn get_slot_by_hash(
        &self,
        hex_hash: HexHash,
        query_mode: QueryMode,
    ) -> RpcResult<Option<Slot>>;

    /// Gets a single batch by hash.
    #[method(name = "getBatchByHash")]
    async fn get_batch_by_hash(
        &self,
        hex_hash: HexHash,
        query_mode: QueryMode,
    ) -> RpcResult<Option<Batch>>;

    /// Gets a single transaction by hash.
    #[method(name = "getTransactionByHash")]
    async fn get_tx_by_hash(
        &self,
        hex_hash: HexHash,
        query_mode: QueryMode,
    ) -> RpcResult<Option<Tx>>;

    /// Gets a single slot by number.
    #[method(name = "getSlotByNumber")]
    async fn get_slot_by_number(
        &self,
        number: u64,
        query_mode: QueryMode,
    ) -> RpcResult<Option<Slot>>;

    /// Gets a single batch by number.
    #[method(name = "getBatchByNumber")]
    async fn get_batch_by_number(
        &self,
        number: u64,
        query_mode: QueryMode,
    ) -> RpcResult<Option<Batch>>;

    /// Gets a single event by number.
    #[method(name = "getEventByNumber")]
    async fn get_event_by_number(&self, number: u64) -> RpcResult<Option<Event>>;

    /// Gets a single tx by number.
    #[method(name = "getTransactionByNumber")]
    async fn get_tx_by_number(&self, number: u64, query_mode: QueryMode) -> RpcResult<Option<Tx>>;

    /// Gets a range of slots. This query is the most efficient way to
    /// fetch large numbers of slots, since it allows for easy batching of
    /// db queries for adjacent items.
    #[method(name = "getSlotsRange")]
    async fn get_slots_range(
        &self,
        start: u64,
        end: u64,
        query_mode: QueryMode,
    ) -> RpcResult<Vec<Option<Slot>>>;

    /// Gets a range of batches. This query is the most efficient way to
    /// fetch large numbers of batches, since it allows for easy batching of
    /// db queries for adjacent items.
    #[method(name = "getBatchesRange")]
    async fn get_batches_range(
        &self,
        start: u64,
        end: u64,
        query_mode: QueryMode,
    ) -> RpcResult<Vec<Option<Batch>>>;

    /// Gets a range of transactions. This query is the most efficient way to
    /// fetch large numbers of transactions, since it allows for easy batching of
    /// db queries for adjacent items.
    #[method(name = "getTransactionsRange")]
    async fn get_txs_range(
        &self,
        start: u64,
        end: u64,
        query_mode: QueryMode,
    ) -> RpcResult<Vec<Option<Tx>>>;

    /// Gets a single event by number.
    #[method(name = "getSoftConfirmationStatus")]
    async fn get_soft_confirmation_status(
        &self,
        soft_batch_receipt: u64,
    ) -> RpcResult<SoftConfirmationStatus>;

    /// Subscription method to receive a notification each time a slot is
    /// processed.
    #[subscription(name = "subscribeSlots", item = u64)]
    async fn subscribe_slots(&self) -> SubscriptionResult;
}
