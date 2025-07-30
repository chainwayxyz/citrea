// https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc-types/src/eth/filter.rs

use std::env;
use std::iter::StepBy;
use std::ops::RangeInclusive;

use alloy_eips::BlockNumberOrTag;
use reth_rpc::eth::filter::EthFilterError;

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
