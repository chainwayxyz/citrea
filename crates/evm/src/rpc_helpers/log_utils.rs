// Like reth v1.3.7, use the current head as the upper bound independently of the cursor.
// https://github.com/paradigmxyz/reth/blob/v1.3.7/crates/rpc/rpc-eth-types/src/logs_utils.rs#L159-L184

/// Computes the block range based on the filter range, starting block, and current head.
pub fn get_filter_block_range(
    from_block: Option<u64>,
    to_block: Option<u64>,
    start_block: u64,
    head_block: u64,
) -> (u64, u64) {
    let mut from_block_number = start_block;
    let mut to_block_number = head_block;

    // if a `from_block` argument is provided then the `from_block_number` is the converted value or
    // the start block if the converted value is larger than the start block, since `from_block`
    // can't be a future block: `min(head, from_block)`
    if let Some(filter_from_block) = from_block {
        from_block_number = start_block.min(filter_from_block)
    }

    // upper end of the range is the converted `to_block` argument, restricted by the best block:
    // `min(best_number,to_block_number)`
    if let Some(filter_to_block) = to_block {
        to_block_number = head_block.min(filter_to_block);
    }

    (from_block_number, to_block_number)
}
