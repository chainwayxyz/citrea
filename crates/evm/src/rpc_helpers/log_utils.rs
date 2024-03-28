// https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc/src/eth/logs_utils.rs

/// Computes the block range based on the filter range and current block numbers
pub fn get_filter_block_range(
    from_block: Option<u64>,
    to_block: Option<u64>,
    start_block: u64,
) -> (u64, u64) {
    let mut from_block_number = start_block;
    let mut to_block_number = start_block;

    // if a `from_block` argument is provided then the `from_block_number` is the converted value or
    // the start block if the converted value is larger than the start block, since `from_block`
    // can't be a future block: `min(head, from_block)`
    if let Some(filter_from_block) = from_block {
        from_block_number = start_block.min(filter_from_block)
    }

    // upper end of the range is the converted `to_block` argument, restricted by the best block:
    // `min(best_number,to_block_number)`
    if let Some(filter_to_block) = to_block {
        to_block_number = start_block.min(filter_to_block);
    }

    (from_block_number, to_block_number)
}
