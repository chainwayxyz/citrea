/// This defines the interface of a pruning criteria.
pub(crate) trait Criteria {
    /// Decides whether pruning should be done or not.
    ///
    /// If None is returned, no pruning should happen.
    /// Otherwise, it will return the `up_to_block` value.
    fn should_prune(&self, last_pruned_block: u64, current_block_number: u64) -> Option<u64>;
}

/// This distance criteria prunes a number of blocks
pub(crate) struct DistanceCriteria {
    pub(crate) distance: u64,
}

impl Criteria for DistanceCriteria {
    fn should_prune(&self, last_pruned_block: u64, current_block_number: u64) -> Option<u64> {
        let trigger_block = last_pruned_block + (2 * self.distance) + 1;
        if current_block_number >= trigger_block {
            return Some(last_pruned_block + self.distance);
        }
        return None;
    }
}
