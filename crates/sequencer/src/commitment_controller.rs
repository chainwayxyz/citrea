use std::ops::RangeInclusive;

use anyhow::anyhow;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::LedgerDB;
use sov_db::schema::types::BatchNumber;
use sov_rollup_interface::da::SequencerCommitment;
use tracing::{debug, instrument};

#[derive(Clone, Debug)]
pub struct CommitmentInfo {
    /// L2 heights to commit
    pub l2_height_range: RangeInclusive<BatchNumber>,
}

/// Checks if the sequencer should commit
/// Returns none if the commitable L2 block range is shorter than `min_soft_confirmations_per_commitment`
/// Returns `CommitmentInfo` if the sequencer should commit
#[instrument(level = "debug", skip_all, fields(prev_l1_height), err)]
pub fn get_commitment_info(
    ledger_db: &LedgerDB,
    min_soft_confirmations_per_commitment: u64,
    state_diff_threshold_reached: bool,
) -> anyhow::Result<Option<CommitmentInfo>> {
    let Some((head_soft_batch_number, _)) = ledger_db.get_head_soft_batch()? else {
        // No soft batches have been created yet.
        return Ok(None);
    };

    // If last commited l2 height is not passed, query it from ledger db
    // to calculate l2 block range to commit
    let last_committed_l2_height = ledger_db
            .get_last_sequencer_commitment_l2_height()?
            .unwrap_or(BatchNumber(0));

    // If the last commitment made is on par with the head
    // soft batch, we have already committed the latest block.
    if last_committed_l2_height >= head_soft_batch_number {
        // Already committed.
        return Ok(None);
    }

    let l2_start = last_committed_l2_height.0 + 1;
    let l2_end = head_soft_batch_number.0;

    let l2_range_length = 1 + l2_end - l2_start;
    if !state_diff_threshold_reached && (l2_range_length < min_soft_confirmations_per_commitment) {
        return Ok(None);
    }

    if l2_range_length >= min_soft_confirmations_per_commitment {
        debug!("Enough soft confirmations to submit commitment");
    }

    if state_diff_threshold_reached {
        debug!("State diff threshold reached. Committing...");
    }

    Ok(Some(CommitmentInfo {
        l2_height_range: BatchNumber(l2_start)..=BatchNumber(l2_end),
    }))
}

#[instrument(level = "debug", skip_all, err)]
pub fn get_commitment(
    commitment_info: CommitmentInfo,
    soft_confirmation_hashes: Vec<[u8; 32]>,
) -> anyhow::Result<SequencerCommitment> {
    // sanity check
    assert_eq!(
        commitment_info.l2_height_range.end().0 - commitment_info.l2_height_range.start().0 + 1u64,
        soft_confirmation_hashes.len() as u64,
        "Sequencer: Soft confirmation hashes length does not match the commitment info"
    );

    // build merkle tree over soft confirmations
    let merkle_root = MerkleTree::<Sha256>::from_leaves(soft_confirmation_hashes.as_slice())
        .root()
        .ok_or(anyhow!("Couldn't compute merkle root"))?;
    Ok(SequencerCommitment {
        merkle_root,
        l2_start_block_number: commitment_info.l2_height_range.start().0,
        l2_end_block_number: commitment_info.l2_height_range.end().0,
    })
}
