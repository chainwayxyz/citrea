//! Consist of types adjacent to the fee history cache and its configs
use ethers::types::H256;
use reth_primitives::{Receipt, SealedBlock, TransactionSigned, U256};
use reth_rpc_types::{
    Block, BlockTransactions, Rich, Transaction, TransactionReceipt, TxGasAndReward,
};
use serde::{Deserialize, Serialize};
use sov_evm::EthApiError;
use sov_modules_api::WorkingSet;
use std::{
    collections::BTreeMap,
    fmt::Debug,
    sync::{
        atomic::{AtomicU64, Ordering::SeqCst},
        Arc,
    },
};

use super::{
    cache::BlockCache,
    gas_oracle::{
        convert_u256_to_u128, convert_u256_to_u64, effective_gas_tip, MAX_HEADER_HISTORY,
    },
};

/// Settings for the [FeeHistoryCache].
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeHistoryCacheConfig {
    /// Max number of blocks in cache.
    ///
    /// Default is [MAX_HEADER_HISTORY] plus some change to also serve slightly older blocks from
    /// cache, since fee_history supports the entire range
    pub max_blocks: u64,
    /// Percentile approximation resolution
    ///
    /// Default is 4 which means 0.25
    pub resolution: u64,
}

impl Default for FeeHistoryCacheConfig {
    fn default() -> Self {
        FeeHistoryCacheConfig {
            max_blocks: MAX_HEADER_HISTORY + 100,
            resolution: 4,
        }
    }
}

/// Wrapper struct for BTreeMap
pub struct FeeHistoryCache<C: sov_modules_api::Context> {
    inner: Arc<FeeHistoryCacheInner>,
    block_cache: Arc<BlockCache<C>>,
}

impl<C: sov_modules_api::Context> FeeHistoryCache<C> {
    /// Creates new FeeHistoryCache instance, initialize it with the mose recent data, set bounds
    pub fn new(config: FeeHistoryCacheConfig, block_cache: Arc<BlockCache<C>>) -> Self {
        let inner = FeeHistoryCacheInner {
            lower_bound: Default::default(),
            upper_bound: Default::default(),
            config,
            entries: Default::default(),
        };
        Self {
            inner: Arc::new(inner),
            block_cache,
        }
    }

    /// How the cache is configured.
    #[inline]
    pub fn config(&self) -> &FeeHistoryCacheConfig {
        &self.inner.config
    }

    /// Returns the configured resolution for percentile approximation.
    #[inline]
    pub fn resolution(&self) -> u64 {
        self.config().resolution
    }

    /// Processing of the arriving blocks
    pub async fn insert_blocks<I>(&self, blocks: I)
    where
        I: Iterator<Item = (Rich<Block>, Vec<TransactionReceipt>)>,
    {
        let mut entries = self.inner.entries.write().await;

        let percentiles = self.predefined_percentiles();
        // Insert all new blocks and calculate approximated rewards
        for (block, receipts) in blocks {
            let mut fee_history_entry = FeeHistoryEntry::new(&block);
            let transactions = match &block.transactions {
                BlockTransactions::Full(transactions) => transactions,
                _ => unreachable!(),
            };
            fee_history_entry.rewards = calculate_reward_percentiles_for_block(
                &percentiles,
                fee_history_entry.gas_used,
                fee_history_entry.base_fee_per_gas,
                transactions,
                &receipts,
            )
            .unwrap_or_default();
            let block_number =
                convert_u256_to_u64(block.header.number.unwrap_or_default()).unwrap_or_default();
            entries.insert(block_number, fee_history_entry);
        }

        // enforce bounds by popping the oldest entries
        while entries.len() > self.inner.config.max_blocks as usize {
            entries.pop_first();
        }

        if entries.len() == 0 {
            self.inner.upper_bound.store(0, SeqCst);
            self.inner.lower_bound.store(0, SeqCst);
            return;
        }

        let upper_bound = *entries
            .last_entry()
            .expect("Contains at least one entry")
            .key();
        let lower_bound = *entries
            .first_entry()
            .expect("Contains at least one entry")
            .key();
        self.inner.upper_bound.store(upper_bound, SeqCst);
        self.inner.lower_bound.store(lower_bound, SeqCst);
    }

    /// Get UpperBound value for FeeHistoryCache
    pub fn upper_bound(&self) -> u64 {
        self.inner.upper_bound.load(SeqCst)
    }

    /// Get LowerBound value for FeeHistoryCache
    pub fn lower_bound(&self) -> u64 {
        self.inner.lower_bound.load(SeqCst)
    }

    /// Collect fee history for given range.
    ///
    /// This function retrieves fee history entries from the cache for the specified range.
    /// If the requested range (start_block to end_block) is within the cache bounds,
    /// it returns the corresponding entries.
    /// Otherwise it returns None.
    pub async fn get_history(
        &self,
        start_block: u64,
        end_block: u64,
        working_set: &mut WorkingSet<C>,
    ) -> Option<Vec<FeeHistoryEntry>> {
        let lower_bound = self.lower_bound();
        let upper_bound = self.upper_bound();
        if start_block >= lower_bound && end_block <= upper_bound {
            let entries = self.inner.entries.read().await;

            // Find empty blocks heights in the range
            let blocks_with_receipts = entries
                .range(start_block..=end_block)
                .filter(|(_, entry)| entry.gas_used == 0)
                .map(|(block_number, _)| *block_number)
                // Get block with receipts from cache
                .filter_map(|block_number| {
                    self.block_cache
                        .get_block_with_receipts(block_number, working_set)
                        .unwrap_or(None)
                });

            // Insert blocks with receipts into cache
            self.insert_blocks(blocks_with_receipts).await;

            let result = entries
                .range(start_block..=end_block + 1)
                .map(|(_, fee_entry)| fee_entry.clone())
                .collect::<Vec<_>>();

            if result.is_empty() {
                return None;
            }

            Some(result)
        } else {
            None
        }
    }

    /// Generates predefined set of percentiles
    ///
    /// This returns 100 * resolution points
    pub fn predefined_percentiles(&self) -> Vec<f64> {
        let res = self.resolution() as f64;
        (0..=100 * self.resolution())
            .map(|p| p as f64 / res)
            .collect()
    }
}

/// Container type for shared state in [FeeHistoryCache]
#[derive(Debug)]
struct FeeHistoryCacheInner {
    /// Stores the lower bound of the cache
    lower_bound: AtomicU64,
    upper_bound: AtomicU64,
    /// Config for FeeHistoryCache, consists of resolution for percentile approximation
    /// and max number of blocks
    config: FeeHistoryCacheConfig,
    /// Stores the entries of the cache
    entries: tokio::sync::RwLock<BTreeMap<u64, FeeHistoryEntry>>,
}

/// Calculates reward percentiles for transactions in a block header.
/// Given a list of percentiles and a sealed block header, this function computes
/// the corresponding rewards for the transactions at each percentile.
///
/// The results are returned as a vector of U256 values.
pub(crate) fn calculate_reward_percentiles_for_block(
    percentiles: &[f64],
    gas_used: u64,
    base_fee_per_gas: u64,
    transactions: &[Transaction],
    receipts: &[TransactionReceipt],
) -> Result<Vec<U256>, EthApiError> {
    let mut transactions = transactions
        .iter()
        .zip(receipts)
        .scan(0, |previous_gas, (tx, receipt)| {
            // Convert the cumulative gas used in the receipts
            // to the gas usage by the transaction
            //
            // While we will sum up the gas again later, it is worth
            // noting that the order of the transactions will be different,
            // so the sum will also be different for each receipt.
            let cumulative_gas_used =
                convert_u256_to_u64(receipt.cumulative_gas_used).unwrap_or_default();
            let gas_used = cumulative_gas_used - *previous_gas;
            *previous_gas = cumulative_gas_used;

            Some(TxGasAndReward {
                gas_used,
                reward: convert_u256_to_u128(
                    effective_gas_tip(tx, Some(U256::from(base_fee_per_gas))).unwrap_or_default(),
                )
                .unwrap(),
            })
        })
        .collect::<Vec<_>>();

    // Sort the transactions by their rewards in ascending order
    transactions.sort_by_key(|tx| tx.reward);

    // Find the transaction that corresponds to the given percentile
    //
    // We use a `tx_index` here that is shared across all percentiles, since we know
    // the percentiles are monotonically increasing.
    let mut tx_index = 0;
    let mut cumulative_gas_used = transactions
        .first()
        .map(|tx| tx.gas_used)
        .unwrap_or_default();
    let mut rewards_in_block = Vec::new();
    for percentile in percentiles {
        // Empty blocks should return in a zero row
        if transactions.is_empty() {
            rewards_in_block.push(U256::ZERO);
            continue;
        }

        let threshold = (gas_used as f64 * percentile / 100.) as u64;
        while cumulative_gas_used < threshold && tx_index < transactions.len() - 1 {
            tx_index += 1;
            cumulative_gas_used += transactions[tx_index].gas_used;
        }
        rewards_in_block.push(U256::from(transactions[tx_index].reward));
    }

    Ok(rewards_in_block)
}

/// A cached entry for a block's fee history.
#[derive(Debug, Clone)]
pub struct FeeHistoryEntry {
    /// The base fee per gas for this block.
    pub base_fee_per_gas: u64,
    /// Gas used ratio this block.
    pub gas_used_ratio: f64,
    /// Gas used by this block.
    pub gas_used: u64,
    /// Gas limit by this block.
    pub gas_limit: u64,
    /// Hash of the block.
    pub header_hash: H256,
    /// Approximated rewards for the configured percentiles.
    pub rewards: Vec<U256>,
}

impl FeeHistoryEntry {
    /// Creates a new entry from a sealed block.
    ///
    /// Note: This does not calculate the rewards for the block.
    pub fn new(block: &Rich<Block>) -> Self {
        let base_fee_per_gas =
            convert_u256_to_u64(block.header.base_fee_per_gas.unwrap_or_default()).unwrap();

        let gas_used = convert_u256_to_u64(block.header.gas_used).unwrap_or_default();
        let gas_limit = convert_u256_to_u64(block.header.gas_limit).unwrap_or_default();
        let gas_used_ratio = gas_used as f64 / gas_limit as f64;

        FeeHistoryEntry {
            base_fee_per_gas: base_fee_per_gas,
            gas_used_ratio,
            gas_used,
            header_hash: block.header.hash.unwrap_or_default().into(),
            gas_limit,
            rewards: Vec::new(),
        }
    }
}
