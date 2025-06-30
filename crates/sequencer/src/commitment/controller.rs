use std::mem;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use citrea_common::utils::merge_state_diffs;
use citrea_primitives::compression::compress_blob;
use citrea_primitives::MAX_TX_BODY_SIZE;
use parking_lot::Mutex;
use sov_db::ledger_db::SequencerLedgerOps;
use sov_db::schema::types::L2BlockNumber;
use sov_modules_api::StateDiff;
use tracing::debug;

use super::helpers::load_next_commitment_index_and_start_height;
use super::service::CommitmentRange;

// Based on the test runs, brotli is able to compress the state diff 58% to 70%,
// with an average of 66% for both empty and full blocks. This is a super safe
// estimation of 50% compression.
/// Maximum size (in bytes) for an uncompressed transaction body to be considered safe
const SAFE_MAX_UNCOMPRESSED_TXBODY_SIZE: usize = MAX_TX_BODY_SIZE * 2;

/// Controller that manages commitment operations and maintains commitment state
pub struct CommitmentController<Db>
where
    Db: SequencerLedgerOps,
{
    /// The ledger database interface for state operations
    ledger_db: Db,
    /// Maximum number of L2 blocks that can be included in a single commitment
    max_l2_blocks: u64,
    /// Atomic counter for tracking the index of the next commitment
    next_commitment_index: AtomicU32,
    /// Atomic counter for tracking the starting height of the next commitment
    next_commitment_start_height: AtomicU64,
    /// Atomic counter for tracking the last processed L2 block height
    last_l2_height: AtomicU64,
    /// Thread-safe storage for the current state diff
    state_diff: Mutex<StateDiff>,
}

impl<Db> CommitmentController<Db>
where
    Db: SequencerLedgerOps,
{
    /// Creates a new `CommitmentController` with the state set to the last known commitment.
    /// This doesn't immediately catch up to the head block as for any arbitrary reason from
    /// last known commitment to head block, there might be the need to trigger multiple commitments.
    /// Hence, for simplicity, catching up to head on start is left to the caller using `should_commit`.
    pub fn new(ledger_db: Db, max_l2_blocks: u64) -> Self {
        let (next_index, next_start_height) =
            load_next_commitment_index_and_start_height(&ledger_db);
        Self {
            ledger_db,
            max_l2_blocks,
            next_commitment_index: AtomicU32::new(next_index),
            next_commitment_start_height: AtomicU64::new(next_start_height),
            last_l2_height: AtomicU64::new(next_start_height - 1),
            state_diff: Mutex::new(StateDiff::new()),
        }
    }

    /// Checks if with the new l2 height a commitment can be triggered.
    /// This function must be called with consecutive l2 heights, else it panics.
    pub fn should_commit(
        &self,
        l2_height: L2BlockNumber,
    ) -> anyhow::Result<Option<(u32, CommitmentRange)>> {
        let last_l2_height = self.last_l2_height.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            l2_height.0,
            last_l2_height + 1,
            "CommitmentController is called with non-consecutive l2 heights"
        );

        let range = match self.check_state_diff_threshold(l2_height)? {
            Some(range) => range,
            None => match self.check_max_l2_blocks(l2_height) {
                Some(range) => {
                    // we clear the state diff when max l2 blocks triggers commitment
                    *self.state_diff.lock() = vec![];
                    range
                }
                None => return Ok(None),
            },
        };

        let index = self.next_commitment_index.fetch_add(1, Ordering::SeqCst);
        self.next_commitment_start_height
            .store(range.end().0 + 1, Ordering::SeqCst);

        Ok(Some((index, range)))
    }

    /// Checks if with the new l2 height state diff threshold is reached.
    /// This function expects l2 height consecutivity to be already checked.
    fn check_state_diff_threshold(
        &self,
        l2_height: L2BlockNumber,
    ) -> anyhow::Result<Option<CommitmentRange>> {
        let mut accumulated_diff = self.state_diff.lock();

        let state_diff = self.ledger_db.get_state_diff(l2_height)?;
        *accumulated_diff = merge_state_diffs(mem::take(&mut accumulated_diff), state_diff.clone());

        let uncompressed_state_diff = borsh::to_vec(accumulated_diff.as_slice())
            .expect("State diff serialization can not fail");
        // early return if uncompressed state diff doesn't exceed safe limit
        if uncompressed_state_diff.len() <= SAFE_MAX_UNCOMPRESSED_TXBODY_SIZE {
            return Ok(None);
        }

        let compressed_state_diff = compress_blob(&uncompressed_state_diff).unwrap();
        if compressed_state_diff.len() <= MAX_TX_BODY_SIZE {
            return Ok(None);
        }

        // when state diff threshold is exceeded, the final block is excluded from the commitment,
        // hence, the new state diff becomes the last l2 block's state diff
        *accumulated_diff = state_diff;

        debug!("Enough state diff to submit commitment");

        Ok(Some(
            L2BlockNumber(self.next_commitment_start_height())..=L2BlockNumber(l2_height.0 - 1),
        ))
    }

    /// Checks if the maximum number of L2 blocks limit has been reached
    ///
    /// Returns a commitment range (start and end block numbers) if the limit is reached,
    /// otherwise returns None.
    ///
    /// # Arguments
    /// * `l2_height` - Current L2 block height to check against
    fn check_max_l2_blocks(&self, l2_height: L2BlockNumber) -> Option<CommitmentRange> {
        let l2_start = self.next_commitment_start_height();
        let l2_end = l2_height.0;

        assert!(
            l2_end >= l2_start,
            "Got L2 height lower than the last committed L2 height."
        );

        let l2_range_length = 1 + l2_end - l2_start;
        if l2_range_length < self.max_l2_blocks {
            return None;
        }

        debug!("Enough l2 blocks to submit commitment");

        Some(L2BlockNumber(l2_start)..=L2BlockNumber(l2_end))
    }

    /// Gets the starting height for the next commitment
    ///
    /// # Returns
    /// The L2 block height where the next commitment should start
    #[inline(always)]
    fn next_commitment_start_height(&self) -> u64 {
        self.next_commitment_start_height.load(Ordering::SeqCst)
    }

    /// Gets the last processed L2 block height
    ///
    /// # Returns
    /// The height of the last L2 block that was processed
    #[inline(always)]
    pub(crate) fn last_l2_height(&self) -> u64 {
        self.last_l2_height.load(Ordering::SeqCst)
    }
}
