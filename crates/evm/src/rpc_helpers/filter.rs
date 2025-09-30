// https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc-types/src/eth/filter.rs

use std::collections::HashMap;
use std::iter::StepBy;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Instant;
use std::{env, fmt};

use alloy_eips::BlockNumberOrTag;
use alloy_primitives::TxHash;
use alloy_rpc_types::{Filter, FilterChanges, FilterId};
use async_trait::async_trait;
use reth_rpc::eth::filter::EthFilterError;
use reth_rpc_eth_api::TransactionCompat;
use reth_transaction_pool::{NewSubpoolTransactionStream, PoolTransaction};
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;

/// The maximum number of blocks that can be queried in a single eth_getLogs request.
pub const DEFAULT_MAX_BLOCKS_PER_FILTER: u64 = 1_000;
/// The maximum number of logs that can be returned in a single eth_getLogs response.
pub const DEFAULT_MAX_LOGS_PER_RESPONSE: usize = 5_000;
/// The maximum number of headers we read at once when handling a range filter.
pub const DEFAULT_MAX_HEADERS_RANGE: u64 = 1_000; // with ~530bytes? per header this is ~500kb?

/// Retrieves the maximum number of blocks that can be queried in a single eth_getLogs request.
/// This value can be configured via the `ETH_RPC_MAX_BLOCKS_PER_FILTER` environment variable.
/// If the variable is not set, it defaults to `DEFAULT_MAX_BLOCKS_PER_FILTER`.
pub fn get_max_blocks_per_filter() -> u64 {
    env::var("ETH_RPC_MAX_BLOCKS_PER_FILTER").map_or(DEFAULT_MAX_BLOCKS_PER_FILTER, |v| {
        v.parse()
            .expect("ETH_RPC_MAX_BLOCKS_PER_FILTER must be a valid u64")
    })
}

/// The maximum number of logs that can be returned in a single eth_getLogs response.
/// This value can be configured via the `ETH_RPC_MAX_LOGS_PER_RESPONSE` environment variable.
/// If the variable is not set, it defaults to `DEFAULT_MAX_LOGS_PER_RESPONSE`.
pub fn get_max_logs_per_response() -> usize {
    env::var("ETH_RPC_MAX_LOGS_PER_RESPONSE").map_or(DEFAULT_MAX_LOGS_PER_RESPONSE, |v| {
        v.parse()
            .expect("ETH_RPC_MAX_LOGS_PER_RESPONSE must be a valid usize")
    })
}

/// The maximum number of headers we read at once when handling a range filter.
/// This value can be configured via the `ETH_RPC_MAX_HEADERS_RANGE` environment variable.
/// If the variable is not set, it defaults to `DEFAULT_MAX_HEADERS_RANGE`.
pub fn get_max_headers_range() -> u64 {
    env::var("ETH_RPC_MAX_HEADERS_RANGE").map_or(DEFAULT_MAX_HEADERS_RANGE, |v| {
        v.parse()
            .expect("ETH_RPC_MAX_HEADERS_RANGE must be a valid u64")
    })
}

/// An iterator that yields _inclusive_ block ranges of a given step size
#[derive(Debug)]
pub struct BlockRangeInclusiveIter {
    iter: StepBy<RangeInclusive<u64>>,
    step: u64,
    end: u64,
}

impl BlockRangeInclusiveIter {
    /// Creates a new iterator that yields inclusive block ranges of a specified step size.
    ///
    /// This iterator is useful for processing large block ranges in smaller chunks,
    /// which helps manage memory usage and processing time.
    ///
    /// # Arguments
    ///
    /// * `range` - The inclusive range of block numbers to iterate over
    /// * `step` - The maximum size of each sub-range (chunk)
    ///
    /// # Returns
    ///
    /// Returns an iterator that yields tuples of (start, end) block numbers,
    /// where each sub-range has at most `step + 1` blocks.
    ///
    /// # Example
    ///
    /// ```
    /// let iter = BlockRangeInclusiveIter::new(0..=10, 3);
    /// // This will yield: (0, 3), (4, 7), (8, 10)
    /// ```
    pub fn new(range: RangeInclusive<u64>, step: u64) -> Self {
        Self {
            end: *range.end(),
            iter: range.step_by(step as usize + 1),
            step,
        }
    }
}

impl Iterator for BlockRangeInclusiveIter {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.iter.next()?;
        let end = (start + self.step).min(self.end);
        if start > end {
            return None;
        }
        Some((start, end))
    }
}

/// Converts a block number or tag to a block number. The conversion is done by
/// replacing the tag with the block number.
pub fn convert_block_number(
    num: BlockNumberOrTag,
    start_block: u64,
) -> Result<Option<u64>, EthFilterError> {
    let num = match num {
        BlockNumberOrTag::Latest => start_block,
        BlockNumberOrTag::Earliest => 0,
        // Is this okay? start_block + 1 = Latest blocks number + 1
        BlockNumberOrTag::Pending => start_block + 1,
        BlockNumberOrTag::Number(num) => num,
        // TODO: Is there a better way to handle this instead of giving the latest block?
        BlockNumberOrTag::Finalized => start_block,
        // TODO: Is there a better way to handle this instead of giving the latest block?
        BlockNumberOrTag::Safe => start_block,
    };
    Ok(Some(num))
}

/// All active filters
#[derive(Debug, Clone, Default)]
pub struct ActiveFilters<T> {
    inner: Arc<Mutex<HashMap<FilterId, ActiveFilter<T>>>>,
}

impl<T> ActiveFilters<T> {
    /// Returns an empty instance.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::default())),
        }
    }
}

/// An installed filter
#[derive(Debug)]
struct ActiveFilter<T> {
    /// At which block the filter was polled last.
    block: u64,
    /// Last time this filter was polled.
    last_poll_timestamp: Instant,
    /// What kind of filter it is.
    kind: FilterKind<T>,
}

/// A receiver for pending transactions that returns all new transactions since the last poll.
#[derive(Debug, Clone)]
struct PendingTransactionsReceiver {
    txs_receiver: Arc<Mutex<Receiver<TxHash>>>,
}

impl PendingTransactionsReceiver {
    fn new(receiver: Receiver<TxHash>) -> Self {
        Self {
            txs_receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    /// Returns all new pending transactions received since the last poll.
    async fn drain<T>(&self) -> FilterChanges<T> {
        let mut pending_txs = Vec::new();
        let mut prepared_stream = self.txs_receiver.lock().await;

        while let Ok(tx_hash) = prepared_stream.try_recv() {
            pending_txs.push(tx_hash);
        }

        // Convert the vector of hashes into FilterChanges::Hashes
        FilterChanges::Hashes(pending_txs)
    }
}

/// A structure to manage and provide access to a stream of full transaction details.
#[derive(Debug, Clone)]
struct FullTransactionsReceiver<T: PoolTransaction, TxCompat> {
    txs_stream: Arc<Mutex<NewSubpoolTransactionStream<T>>>,
    tx_resp_builder: TxCompat,
}

impl<T, TxCompat> FullTransactionsReceiver<T, TxCompat>
where
    T: PoolTransaction + 'static,
    TxCompat: TransactionCompat<T::Consensus>,
{
    /// Creates a new `FullTransactionsReceiver` encapsulating the provided transaction stream.
    fn new(stream: NewSubpoolTransactionStream<T>, tx_resp_builder: TxCompat) -> Self {
        Self {
            txs_stream: Arc::new(Mutex::new(stream)),
            tx_resp_builder,
        }
    }

    /// Returns all new pending transactions received since the last poll.
    async fn drain(&self) -> FilterChanges<TxCompat::Transaction> {
        let mut pending_txs = Vec::new();
        let mut prepared_stream = self.txs_stream.lock().await;

        while let Ok(tx) = prepared_stream.try_recv() {
            match self
                .tx_resp_builder
                .fill_pending(tx.transaction.to_consensus())
            {
                Ok(tx) => pending_txs.push(tx),
                Err(err) => {
                    tracing::error!(target: "rpc",
                        %err,
                        "Failed to fill txn with block context"
                    );
                }
            }
        }
        FilterChanges::Transactions(pending_txs)
    }
}

/// Helper trait for [FullTransactionsReceiver] to erase the `Transaction` type.
#[async_trait]
trait FullTransactionsFilter<T>: fmt::Debug + Send + Sync + Unpin + 'static {
    async fn drain(&self) -> FilterChanges<T>;
}

#[async_trait]
impl<T, TxCompat> FullTransactionsFilter<TxCompat::Transaction>
    for FullTransactionsReceiver<T, TxCompat>
where
    T: PoolTransaction + 'static,
    TxCompat: TransactionCompat<T::Consensus> + 'static,
{
    async fn drain(&self) -> FilterChanges<TxCompat::Transaction> {
        Self::drain(self).await
    }
}

/// Represents the kind of pending transaction data that can be retrieved.
///
/// This enum differentiates between two kinds of pending transaction data:
/// - Just the transaction hashes.
/// - Full transaction details.
#[derive(Debug, Clone)]
enum PendingTransactionKind<T> {
    Hashes(PendingTransactionsReceiver),
    FullTransaction(Arc<dyn FullTransactionsFilter<T>>),
}

impl<T: 'static> PendingTransactionKind<T> {
    async fn drain(&self) -> FilterChanges<T> {
        match self {
            Self::Hashes(receiver) => receiver.drain().await,
            Self::FullTransaction(receiver) => receiver.drain().await,
        }
    }
}

#[derive(Clone, Debug)]
enum FilterKind<T> {
    Log(Box<Filter>),
    Block,
    PendingTransaction(PendingTransactionKind<T>),
}

// TODO:
/// Idea from: https://github.com/paradigmxyz/reth/blob/ed7da87da4de340a437bf46f39a7e1397ac82065/crates/rpc/rpc/src/eth/filter.rs#L382
// pub struct CitreaFilter {
//     pub active_filters:
// }
