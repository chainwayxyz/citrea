//! An implementation of the eth gas price oracle, used for providing gas price estimates based on
//! previous blocks.
#![allow(unused)]

// Adopted from: https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc/src/eth/gas_oracle.rs

use citrea_evm::{Evm, SYSTEM_SIGNER};
use citrea_primitives::basefee::calculate_next_block_base_fee;
use parking_lot::Mutex;
use reth_primitives::{BlockNumberOrTag, B256, U256};
use reth_rpc_eth_types::error::{EthApiError, EthResult, RpcInvalidTransactionError};
use reth_rpc_types::{BlockTransactions, FeeHistory};
use serde::{Deserialize, Serialize};
use sov_modules_api::WorkingSet;
use tracing::warn;

use super::cache::BlockCache;
use super::fee_history::{FeeHistoryCache, FeeHistoryCacheConfig, FeeHistoryEntry};

/// The number of transactions sampled in a block
pub const SAMPLE_NUMBER: u32 = 3;

/// The default maximum number of blocks to use for the gas price oracle.
pub const MAX_HEADER_HISTORY: u64 = 1024;

/// The default maximum gas price to use for the estimate
pub const DEFAULT_MAX_PRICE: U256 = U256::from_limbs([500_000_000_000u64, 0, 0, 0]);

/// The default minimum gas price, under which the sample will be ignored
pub const DEFAULT_IGNORE_PRICE: U256 = U256::from_limbs([2u64, 0, 0, 0]);

/// Settings for the gas price oracle configured by node operators
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GasPriceOracleConfig {
    /// The number of populated blocks to produce the gas price estimate
    pub blocks: u32,

    /// The percentile of gas prices to use for the estimate
    pub percentile: u32,

    /// The maximum number of headers to keep in the cache
    pub max_header_history: u64,

    /// The maximum number of blocks for estimating gas price
    pub max_block_history: u64,

    /// The default gas price to use if there are no blocks to use
    pub default: Option<u128>,

    /// The maximum gas price to use for the estimate
    pub max_price: Option<u128>,

    /// The minimum gas price, under which the sample will be ignored
    pub ignore_price: Option<u128>,
}

impl Default for GasPriceOracleConfig {
    fn default() -> Self {
        GasPriceOracleConfig {
            blocks: 20,
            percentile: 60,
            max_header_history: MAX_HEADER_HISTORY,
            max_block_history: MAX_HEADER_HISTORY,
            default: None,
            max_price: Some(DEFAULT_MAX_PRICE.saturating_to()),
            ignore_price: Some(DEFAULT_IGNORE_PRICE.saturating_to()),
        }
    }
}

impl GasPriceOracleConfig {
    /// Creating a new gpo config with blocks, ignoreprice, maxprice and percentile
    pub fn new(
        blocks: Option<u32>,
        ignore_price: Option<u64>,
        max_price: Option<u64>,
        percentile: Option<u32>,
    ) -> Self {
        Self {
            blocks: blocks.unwrap_or(20),
            percentile: percentile.unwrap_or(60),
            max_header_history: 1024,
            max_block_history: 1024,
            default: None,
            max_price: max_price
                .map(u128::from)
                .or(Some(DEFAULT_MAX_PRICE.saturating_to())),
            ignore_price: ignore_price
                .map(u128::from)
                .or(Some(DEFAULT_IGNORE_PRICE.saturating_to())),
        }
    }
}

/// Calculates a gas price depending on recent blocks.
pub struct GasPriceOracle<C: sov_modules_api::Context> {
    /// The type used to get block and tx info
    provider: Evm<C>,
    /// The config for the oracle
    oracle_config: GasPriceOracleConfig,
    /// The latest calculated price and its block hash
    last_price: Mutex<GasPriceOracleResult>,
    /// Fee history cache with lifetime
    fee_history_cache: Mutex<FeeHistoryCache<C>>,
}

impl<C: sov_modules_api::Context> GasPriceOracle<C> {
    /// Creates and returns the [GasPriceOracle].
    pub fn new(
        provider: Evm<C>,
        mut oracle_config: GasPriceOracleConfig,
        fee_history_config: FeeHistoryCacheConfig,
    ) -> Self {
        // sanitize the percentile to be less than 100
        if oracle_config.percentile > 100 {
            warn!(prev_percentile = ?oracle_config.percentile, "Invalid configured gas price percentile, assuming 100.");
            oracle_config.percentile = 100;
        }

        let max_header_history = oracle_config.max_header_history as u32;

        let block_cache = BlockCache::new(max_header_history, provider.clone());
        let fee_history_cache = FeeHistoryCache::new(fee_history_config, block_cache);

        Self {
            provider: provider.clone(),
            oracle_config,
            last_price: Default::default(),
            fee_history_cache: Mutex::new(fee_history_cache),
        }
    }

    /// Returns the config for the oracle
    pub fn config(&self) -> &GasPriceOracleConfig {
        &self.oracle_config
    }

    /// Reports the fee history
    pub fn fee_history(
        &self,
        mut block_count: u64,
        newest_block: BlockNumberOrTag,
        reward_percentiles: Option<Vec<f64>>,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> EthResult<FeeHistory> {
        if block_count == 0 {
            return Ok(FeeHistory::default());
        }

        // See https://github.com/ethereum/go-ethereum/blob/2754b197c935ee63101cbbca2752338246384fec/eth/gasprice/feehistory.go#L218C8-L225
        let max_fee_history = if reward_percentiles.is_none() {
            self.config().max_header_history
        } else {
            self.config().max_block_history
        };

        if block_count > max_fee_history {
            block_count = max_fee_history
        }

        let end_block = self
            .provider
            .block_number_for_id(&newest_block, working_set)?;

        // need to add 1 to the end block to get the correct (inclusive) range
        let end_block_plus = end_block + 1;
        // Ensure that we would not be querying outside of genesis
        if end_block_plus < block_count {
            block_count = end_block_plus;
        }

        // If reward percentiles were specified, we
        // need to validate that they are monotonically
        // increasing and 0 <= p <= 100
        // Note: The types used ensure that the percentiles are never < 0
        if let Some(percentiles) = &reward_percentiles {
            if percentiles.windows(2).any(|w| w[0] > w[1] || w[0] > 100.) {
                return Err(EthApiError::InvalidRewardPercentiles);
            }
        }

        // Fetch the headers and ensure we got all of them
        //
        // Treat a request for 1 block as a request for `newest_block..=newest_block`,
        // otherwise `newest_block - 2
        // SAFETY: We ensured that block count is capped
        let start_block = end_block_plus - block_count;

        // Collect base fees, gas usage ratios and (optionally) reward percentile data
        let mut base_fee_per_gas: Vec<u128> = Vec::new();
        let mut gas_used_ratio: Vec<f64> = Vec::new();
        let mut rewards: Vec<Vec<u128>> = Vec::new();

        let (fee_entries, resolution) = {
            let mut fee_history_cache = self.fee_history_cache.lock();

            (
                fee_history_cache.get_history(start_block, end_block, working_set),
                fee_history_cache.resolution(),
            )
        };

        if fee_entries.len() != block_count as usize {
            return Err(EthApiError::InvalidBlockRange);
        }

        for entry in &fee_entries {
            base_fee_per_gas.push(entry.base_fee_per_gas as u128);
            gas_used_ratio.push(entry.gas_used_ratio);

            if let Some(percentiles) = &reward_percentiles {
                let mut block_rewards = Vec::with_capacity(percentiles.len());
                for &percentile in percentiles.iter() {
                    block_rewards.push(self.approximate_percentile(entry, percentile, resolution));
                }
                rewards.push(block_rewards);
            }
        }
        let last_entry = fee_entries.last().expect("is not empty");
        base_fee_per_gas.push(calculate_next_block_base_fee(
            last_entry.gas_used as u128,
            last_entry.gas_limit as u128,
            last_entry.base_fee_per_gas,
            self.provider.get_chain_config(working_set).base_fee_params,
        ));

        Ok(FeeHistory {
            base_fee_per_gas,
            gas_used_ratio,
            oldest_block: start_block,
            reward: reward_percentiles.map(|_| rewards),
            base_fee_per_blob_gas: Default::default(),
            blob_gas_used_ratio: Default::default(),
        })
    }

    /// Suggests a gas price estimate based on recent blocks, using the configured percentile.
    pub fn suggest_tip_cap(&self, working_set: &mut WorkingSet<C::Storage>) -> EthResult<u128> {
        let header = &self
            .provider
            .get_block_by_number(None, None, working_set)
            .unwrap()
            .unwrap()
            .header;

        let mut last_price = self.last_price.lock();

        // if we have stored a last price, then we check whether or not it was for the same head
        if last_price.block_hash == header.hash.unwrap() {
            return Ok(last_price.price);
        }

        // if all responses are empty, then we can return a maximum of 2*check_block blocks' worth
        // of prices
        //
        // we only return more than check_block blocks' worth of prices if one or more return empty
        // transactions
        let mut current_hash = header.hash.unwrap();
        let mut results = Vec::new();
        let mut populated_blocks = 0;

        let header_number = header.number.unwrap();

        // we only check a maximum of 2 * max_block_history, or the number of blocks in the chain
        let max_blocks = if self.oracle_config.max_block_history * 2 > header_number {
            header_number
        } else {
            self.oracle_config.max_block_history * 2
        };

        for _ in 0..max_blocks {
            let (parent_hash, block_values) = self
                .get_block_values(current_hash, SAMPLE_NUMBER as usize, working_set)?
                .ok_or(EthApiError::UnknownBlockNumber)?;

            if block_values.is_empty() {
                results.push(last_price.price);
            } else {
                results.extend(block_values);
                populated_blocks += 1;
            }

            // break when we have enough populated blocks
            if populated_blocks >= self.oracle_config.blocks {
                break;
            }

            current_hash = parent_hash;
        }

        // sort results then take the configured percentile result
        let mut price = last_price.price;
        if !results.is_empty() {
            results.sort_unstable();
            price = *results
                .get((results.len() - 1) * self.oracle_config.percentile as usize / 100)
                .expect("gas price index is a percent of nonzero array length, so a value always exists; qed");
        }

        // constrain to the max price
        if let Some(max_price) = self.oracle_config.max_price {
            if price > max_price {
                price = max_price;
            }
        }

        *last_price = GasPriceOracleResult {
            block_hash: header.hash.unwrap(),
            price,
        };

        Ok(price)
    }

    /// Get the `limit` lowest effective tip values for the given block. If the oracle has a
    /// configured `ignore_price` threshold, then tip values under that threshold will be ignored
    /// before returning a result.
    ///
    /// If the block cannot be found, then this will return `None`.
    ///
    /// This method also returns the parent hash for the given block.
    fn get_block_values(
        &self,
        block_hash: B256,
        limit: usize,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> EthResult<Option<(B256, Vec<u128>)>> {
        // check the cache (this will hit the disk if the block is not cached)
        let block_hit = {
            let mut cache = self.fee_history_cache.lock();
            cache.block_cache.get_block(block_hash, working_set)?
        };
        let block = match block_hit {
            Some(block) => block,
            None => return Ok(None),
        };

        // sort the transactions by effective tip
        // but first filter those that should be ignored

        // get the transactions (block.transactions is a enum but we only care about the 2nd arm)
        let txs = match &block.transactions {
            BlockTransactions::Full(txs) => txs,
            _ => return Ok(None),
        };

        let mut txs = txs
            .iter()
            .filter(|tx| {
                if let Some(ignore_under) = self.oracle_config.ignore_price {
                    let effective_gas_tip = effective_gas_tip(tx, block.header.base_fee_per_gas);
                    if effective_gas_tip < Some(ignore_under) {
                        return false;
                    }
                }

                // check if coinbase
                let sender = tx.from;
                sender != block.header.miner && sender != SYSTEM_SIGNER
            })
            // map all values to effective_gas_tip because we will be returning those values
            // anyways
            .map(|tx| effective_gas_tip(tx, block.header.base_fee_per_gas))
            .collect::<Vec<_>>();

        // now do the sort
        txs.sort_unstable();

        // fill result with the top `limit` transactions
        let mut final_result = Vec::with_capacity(limit);
        for tx in txs.iter().take(limit) {
            // a `None` effective_gas_tip represents a transaction where the max_fee_per_gas is
            // less than the base fee
            let effective_tip = tx.ok_or(RpcInvalidTransactionError::FeeCapTooLow)?;
            final_result.push(effective_tip);
        }

        Ok(Some((block.header.parent_hash, final_result)))
    }

    /// Approximates reward at a given percentile for a specific block
    /// Based on the configured resolution
    fn approximate_percentile(
        &self,
        entry: &FeeHistoryEntry,
        requested_percentile: f64,
        resolution: u64,
    ) -> u128 {
        let rounded_percentile =
            (requested_percentile * resolution as f64).round() / resolution as f64;
        let clamped_percentile = rounded_percentile.clamp(0.0, 100.0);

        // Calculate the index in the precomputed rewards array
        let index = (clamped_percentile / (1.0 / resolution as f64)).round() as usize;
        // Fetch the reward from the FeeHistoryEntry
        entry.rewards.get(index).cloned().unwrap_or_default()
    }
}

/// Stores the last result that the oracle returned
#[derive(Debug, Clone)]
pub struct GasPriceOracleResult {
    /// The block hash that the oracle used to calculate the price
    pub block_hash: B256,
    /// The price that the oracle calculated
    pub price: u128,
}

impl Default for GasPriceOracleResult {
    fn default() -> Self {
        Self {
            block_hash: B256::ZERO,
            // Defaults to 0 so that priority fee is low when there are no txs to calculate a median tip
            price: 0_u128,
        }
    }
}

// Adopted from: https://github.com/paradigmxyz/reth/blob/main/crates/primitives/src/transaction/mod.rs#L297
pub(crate) fn effective_gas_tip(
    transaction: &reth_rpc_types::Transaction,
    base_fee: Option<u128>,
) -> Option<u128> {
    let priority_fee_or_price = match transaction.transaction_type {
        Some(tx_type) => {
            if tx_type == 2 {
                transaction.max_priority_fee_per_gas.unwrap()
            } else {
                transaction.gas_price.unwrap()
            }
        }
        _ => transaction.gas_price.unwrap(),
    };

    if let Some(base_fee) = base_fee {
        let max_fee_per_gas = match transaction.transaction_type {
            Some(tx_type) => {
                if tx_type == 2 {
                    transaction.max_priority_fee_per_gas.unwrap()
                } else {
                    transaction.gas_price.unwrap()
                }
            }
            _ => transaction.gas_price.unwrap(),
        };

        if max_fee_per_gas < base_fee {
            None
        } else {
            let effective_max_fee = max_fee_per_gas - base_fee;
            Some(std::cmp::min(effective_max_fee, priority_fee_or_price))
        }
    } else {
        Some(priority_fee_or_price)
    }
}

#[allow(dead_code)]
pub(crate) fn convert_u64_to_u256(u64: u64) -> reth_primitives::U256 {
    let bytes: [u8; 8] = u64.to_be_bytes();
    let mut new_bytes = [0u8; 32];
    new_bytes[24..].copy_from_slice(&bytes);
    reth_primitives::U256::from_be_bytes(new_bytes)
}

#[cfg(test)]
mod tests {
    use reth_primitives::constants::GWEI_TO_WEI;

    use super::*;

    #[test]
    fn max_price_sanity() {
        assert_eq!(DEFAULT_MAX_PRICE, U256::from(500_000_000_000u64));
        assert_eq!(DEFAULT_MAX_PRICE, U256::from(500 * GWEI_TO_WEI))
    }

    #[test]
    fn ignore_price_sanity() {
        assert_eq!(DEFAULT_IGNORE_PRICE, U256::from(2u64));
    }
}
