// https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc-types/src/eth/filter.rs

use std::iter::StepBy;
use std::ops::RangeInclusive;

use alloy_eips::BlockNumberOrTag;
use reth_rpc::eth::filter::EthFilterError;

/// The maximum number of blocks that can be queried in a single eth_getLogs request.
pub const DEFAULT_MAX_BLOCKS_PER_FILTER: u64 = 1_000;
/// The maximum number of logs that can be returned in a single eth_getLogs response.
pub const DEFAULT_MAX_LOGS_PER_RESPONSE: usize = 5_000;
/// The maximum number of headers we read at once when handling a range filter.
pub const MAX_HEADERS_RANGE: u64 = 1_000; // with ~530bytes? per header this is ~500kb?

/// An iterator that yields _inclusive_ block ranges of a given step size
#[derive(Debug)]
pub struct BlockRangeInclusiveIter {
    iter: StepBy<RangeInclusive<u64>>,
    step: u64,
    end: u64,
}

impl BlockRangeInclusiveIter {
    /// TODO: docs
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
