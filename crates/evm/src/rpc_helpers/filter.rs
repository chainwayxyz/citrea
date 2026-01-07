// https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc-types/src/eth/filter.rs

use std::collections::HashMap;
use std::env;
use std::iter::StepBy;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_eips::BlockNumberOrTag;
use alloy_rpc_types::{Filter, FilterBlockOption, FilterChanges, FilterId, Log, Transaction};
use jsonrpsee::core::RpcResult;
use jsonrpsee::server::IdProvider;
use jsonrpsee::types::SubscriptionId;
use reth_rpc::eth::filter::EthFilterError;
use reth_rpc_eth_types::{EthApiError, EthSubscriptionIdProvider};
use reth_tasks::TaskExecutor;
use sov_modules_api::{StateVecAccessor, WorkingSet};
use tokio::sync::RwLock;
use tokio::time::MissedTickBehavior;

use crate::{get_filter_block_range, Evm};

/// The maximum number of blocks that can be queried in a single eth_getLogs request.
pub const DEFAULT_MAX_BLOCKS_PER_FILTER: u64 = 1_000;
/// The maximum number of logs that can be returned in a single eth_getLogs response.
pub const DEFAULT_MAX_LOGS_PER_RESPONSE: usize = 5_000;
/// The maximum number of headers we read at once when handling a range filter.
pub const DEFAULT_MAX_HEADERS_RANGE: u64 = 1_000; // with ~530bytes? per header this is ~500kb?
/// Default value for stale filter ttl
pub const DEFAULT_STALE_FILTER_TTL: Duration = Duration::from_secs(5 * 60);

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
pub struct ActiveFilters {
    inner: Arc<RwLock<HashMap<FilterId, ActiveFilter>>>,
}

impl ActiveFilters {
    /// Returns an empty instance.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::default())),
        }
    }
}

/// An installed filter
#[derive(Debug)]
struct ActiveFilter {
    /// At which block the filter was polled last.
    block: u64,
    /// Last time this filter was polled.
    last_poll_timestamp: Instant,
    /// What kind of filter it is.
    kind: FilterKind,
}

#[derive(Clone, Debug)]
/// The kind of filter
pub enum FilterKind {
    /// Log filter
    Log(Box<Filter>),
    /// Block filter
    Block,
    /// Pending transaction filters are not supported
    /// and will return unsupported error if used.
    PendingTransaction,
}

/// Idea from: https://github.com/paradigmxyz/reth/blob/ed7da87da4de340a437bf46f39a7e1397ac82065/crates/rpc/rpc/src/eth/filter.rs#L382
#[derive(Clone)]
pub struct CitreaFilter {
    /// All currently installed filters.
    pub active_filters: ActiveFilters,
    /// Provides ids to identify filters
    pub id_provider: Arc<dyn IdProvider>,
    /// Task executor to spawn the stale filter clearing task
    pub task_executor: TaskExecutor,
    /// Duration since the last filter poll, after which the filter is considered stale
    pub stale_filter_ttl: Duration,
}

impl CitreaFilter {
    /// Creates a new instance of the CitreaFilter.
    pub fn new(
        task_executor: reth_tasks::TaskExecutor,
        stale_filter_ttl: Option<usize>,
    ) -> CitreaFilter {
        let citrea_filter = CitreaFilter {
            active_filters: ActiveFilters::new(),
            id_provider: Arc::new(EthSubscriptionIdProvider::default()),
            task_executor,
            stale_filter_ttl: stale_filter_ttl
                .map_or(DEFAULT_STALE_FILTER_TTL, |d| Duration::from_secs(d as u64)),
        };

        let this = citrea_filter.clone();
        tracing::trace!("Starting stale filter clearing task ");
        citrea_filter.task_executor.spawn_critical(
            "eth-filters_stale-filters-clean",
            Box::pin(async move {
                this.watch_and_clear_stale_filters().await;
            }),
        );
        citrea_filter
    }

    /// Returns all currently active filters
    pub fn active_filters(&self) -> &ActiveFilters {
        &self.active_filters
    }

    /// Endless future that calls [`Self::clear_stale_filters`] every `stale_filter_ttl` interval.
    /// Nonetheless, this endless future frees the thread at every await point.
    async fn watch_and_clear_stale_filters(&self) {
        tracing::debug!(
            "Starting stale filter clearing task with ttl: {:?}",
            self.stale_filter_ttl
        );
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + self.stale_filter_ttl,
            self.stale_filter_ttl,
        );
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            self.clear_stale_filters(Instant::now()).await;
        }
    }

    /// Clears all filters that have not been polled for longer than the configured
    /// `stale_filter_ttl` at the given instant.
    pub async fn clear_stale_filters(&self, now: Instant) {
        tracing::debug!(target: "clearStaleFilters", "clear stale filters");

        let removed: Vec<(FilterId, ActiveFilter)> = self
            .active_filters()
            .inner
            .write()
            .await
            .extract_if(|_id, filter| (now - filter.last_poll_timestamp) >= self.stale_filter_ttl)
            .collect();

        for (id, _filter) in removed {
            tracing::trace!(target: "clearStaleFilters", "evict filter with id: {:?}", id);
        }
    }

    /// Installs a new filter and returns the new identifier.
    pub async fn install_filter<C: sov_modules_api::Context>(
        &self,
        working_set: &mut WorkingSet<C::Storage>,
        evm: &Evm<C>,
        kind: FilterKind,
    ) -> RpcResult<FilterId> {
        if matches!(kind, FilterKind::PendingTransaction) {
            return Err(EthFilterError::EthAPIError(EthApiError::Unsupported(
                "Pending transaction filters are not supported",
            ))
            .into());
        }
        let last_poll_block_number = evm.last_sealed_header(working_set).number;
        let subscription_id = self.id_provider.next_id();

        let id = match subscription_id {
            SubscriptionId::Num(n) => FilterId::Num(n),
            SubscriptionId::Str(s) => FilterId::Str(s.into_owned()),
        };
        let mut filters = self.active_filters.inner.write().await;
        filters.insert(
            id.clone(),
            ActiveFilter {
                block: last_poll_block_number,
                last_poll_timestamp: Instant::now(),
                kind,
            },
        );
        Ok(id)
    }

    /// Uninstalls a filter with the given id. Returns true if the filter was found and removed,
    /// false otherwise.
    pub async fn uninstall_filter(&self, id: FilterId) -> RpcResult<bool> {
        let mut filters = self.active_filters.inner.write().await;
        if filters.remove(&id).is_some() {
            tracing::trace!(target: "uninstallFilter", ?id, "uninstalled filter");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Returns all the filter changes for the given id, if any
    pub async fn filter_changes<C: sov_modules_api::Context>(
        &self,
        working_set: &mut WorkingSet<C::Storage>,
        evm: &Evm<C>,
        id: FilterId,
    ) -> Result<FilterChanges<Transaction>, EthFilterError> {
        let latest_block_number = evm
            .blocks
            .last(&mut working_set.accessory_state())
            .ok_or(EthFilterError::InternalError)?
            .header
            .number;

        // start_block is the block from which we should start fetching changes, the next block from
        // the last time changes were polled, in other words the best block at last poll + 1
        let (start_block, kind) = {
            let mut filters = self.active_filters.inner.write().await;
            let filter = filters
                .get_mut(&id)
                .ok_or(EthFilterError::FilterNotFound(id.clone()))?;

            if filter.block > latest_block_number {
                // no new blocks since the last poll
                return Ok(FilterChanges::Empty);
            }

            // update filter
            // we fetch all changes from [filter.block..best_block], so we advance the filter's
            // block to `best_block +1`, the next from which we should start fetching changes again
            let start_block = filter.block;
            filter.block = latest_block_number + 1;
            filter.last_poll_timestamp = Instant::now();

            (start_block, filter.kind.clone())
        };

        match kind {
            // Pending transaction filters are not supported
            FilterKind::PendingTransaction => {
                let _ = self.uninstall_filter(id).await;
                Err(
                    EthApiError::Unsupported("Pending transaction filters are not supported")
                        .into(),
                )
            }
            FilterKind::Block => {
                // Note: we need to fetch the block hashes from inclusive range
                // [start_block..latest_block_number]
                let end_block = latest_block_number;
                let block_hashes = evm
                    .sealed_headers_range(start_block..=end_block, working_set)
                    .map_err(|_| {
                        EthApiError::HeaderRangeNotFound(start_block.into(), end_block.into())
                    })?
                    .iter()
                    .map(|h| h.hash())
                    .collect::<Vec<_>>();

                Ok(FilterChanges::Hashes(block_hashes))
            }
            FilterKind::Log(filter) => {
                let (from_block_number, to_block_number) = match filter.block_option {
                    FilterBlockOption::Range {
                        from_block,
                        to_block,
                    } => {
                        let from = from_block
                            .map(|num| convert_block_number(num, start_block))
                            .transpose()?
                            .flatten();
                        let to = to_block
                            .map(|num| convert_block_number(num, latest_block_number))
                            .transpose()?
                            .flatten();
                        get_filter_block_range(from, to, start_block)
                    }
                    FilterBlockOption::AtBlockHash(_) => {
                        // blockHash is equivalent to fromBlock = toBlock = the block number with
                        // hash blockHash
                        // get_logs_in_block_range is inclusive
                        (start_block, latest_block_number)
                    }
                };
                let logs = evm.get_logs_in_block_range(
                    working_set,
                    &filter,
                    from_block_number,
                    to_block_number,
                    get_max_logs_per_response(),
                )?;
                Ok(FilterChanges::Logs(logs))
            }
        }
    }

    /// Returns all the logs for the given filter id, if any
    pub async fn filter_logs<C: sov_modules_api::Context>(
        &self,
        working_set: &mut WorkingSet<C::Storage>,
        evm: &Evm<C>,
        id: FilterId,
    ) -> Result<Vec<Log>, EthFilterError> {
        let filter = {
            let mut filters = self.active_filters.inner.write().await;
            let filter = filters
                .get_mut(&id)
                .ok_or_else(|| EthFilterError::FilterNotFound(id.clone()))?;
            if let FilterKind::Log(ref inner_filter) = filter.kind {
                filter.last_poll_timestamp = Instant::now();
                *inner_filter.clone()
            } else {
                // Not a log filter
                return Err(EthFilterError::FilterNotFound(id));
            }
        };

        evm.logs_for_filter(filter, working_set)
    }
}
