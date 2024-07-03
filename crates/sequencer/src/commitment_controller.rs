use std::ops::RangeInclusive;

use anyhow::{anyhow, bail};
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::LedgerDB;
use sov_db::schema::types::{BatchNumber, SlotNumber};
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::rpc::LedgerRpcProvider;
use tracing::{debug, instrument};

#[derive(Clone, Debug)]
pub struct CommitmentInfo {
    /// L2 heights to commit
    pub l2_height_range: RangeInclusive<BatchNumber>,
    /// Respectfully, the L1 heights to commit.
    /// (L2 blocks were created with these L1 blocks.)
    pub l1_height_range: RangeInclusive<BatchNumber>,
}

/// Checks if the sequencer should commit
/// Returns none if the commitable L2 block range is shorter than `min_soft_confirmations_per_commitment`
/// Returns `CommitmentInfo` if the sequencer should commit
#[instrument(level = "debug", skip_all, fields(prev_l1_height), err)]
pub fn get_commitment_info(
    ledger_db: &LedgerDB,
    min_soft_confirmations_per_commitment: u64,
    prev_l1_height: u64,
) -> anyhow::Result<Option<CommitmentInfo>> {
    // first get when the last merkle root of soft confirmations was submitted
    let last_commitment_l1_height = ledger_db
        .get_last_sequencer_commitment_l1_height()
        .map_err(|e| {
            anyhow!(
                "Sequencer: Failed to get last sequencer commitment L1 height: {}",
                e
            )
        })?;

    debug!("Last commitment L1 height: {:?}", last_commitment_l1_height);

    // if none then we never submitted a commitment, start from prev_l1_height and go back as far as you can go
    // if there is a height then start from height + 1 and go to prev_l1_height
    let (l2_range_to_submit, l1_height_range) = match last_commitment_l1_height {
        Some(last_commitment_l1_height) => {
            let l1_start = last_commitment_l1_height.0 + 1;
            let mut l1_end = l1_start;

            let Some((l2_start, mut l2_end)) =
                ledger_db.get_l2_range_by_l1_height(SlotNumber(l1_start))?
            else {
                return Ok(None);
            };

            // Take while sum of l2 ranges <= min_soft_confirmations_per_commitment
            for l1_i in l1_start..=prev_l1_height {
                l1_end = l1_i;

                let Some((_, l2_end_new)) =
                    ledger_db.get_l2_range_by_l1_height(SlotNumber(l1_end))?
                else {
                    bail!("Sequencer: Failed to get L1 L2 connection");
                };

                l2_end = l2_end_new;

                let l2_range_length = 1 + l2_end.0 - l2_start.0;
                if l2_range_length >= min_soft_confirmations_per_commitment {
                    break;
                }
            }
            let l1_height_range = (l1_start, l1_end);

            let l2_height_range = (l2_start, l2_end);

            (l2_height_range, l1_height_range)
        }
        None => {
            let first_soft_confirmation = match ledger_db.get_soft_batch_by_number::<()>(1)? {
                Some(batch) => batch,
                None => return Ok(None), // not even the first soft confirmation is there, shouldn't happen actually
            };

            let l1_height_range = (first_soft_confirmation.da_slot_height, prev_l1_height);

            let Some((_, last_soft_confirmation_height)) =
                ledger_db.get_l2_range_by_l1_height(SlotNumber(prev_l1_height))?
            else {
                bail!("Sequencer: Failed to get L1 L2 connection");
            };

            let l2_range_to_submit = (BatchNumber(1), last_soft_confirmation_height);

            (l2_range_to_submit, l1_height_range)
        }
    };

    debug!("L2 range to submit: {:?}", l2_range_to_submit);
    debug!("L1 height range: {:?}", l1_height_range);

    if (l2_range_to_submit.1 .0 + 1)
        < min_soft_confirmations_per_commitment + l2_range_to_submit.0 .0
    {
        return Ok(None);
    }

    let Some(l1_start_hash) = ledger_db
        .get_soft_batch_by_number::<()>(l2_range_to_submit.0 .0)?
        .map(|s| s.da_slot_hash)
    else {
        bail!("Failed to get soft batch");
    };

    let Some(l1_end_hash) = ledger_db
        .get_soft_batch_by_number::<()>(l2_range_to_submit.1 .0)?
        .map(|s| s.da_slot_hash)
    else {
        bail!("Failed to get soft batch");
    };

    debug!("L1 start hash: {:?}", l1_start_hash);
    debug!("L1 end hash: {:?}", l1_end_hash);

    Ok(Some(CommitmentInfo {
        l2_height_range: l2_range_to_submit.0..=l2_range_to_submit.1,
        l1_height_range: BatchNumber(l1_height_range.0)..=BatchNumber(l1_height_range.1),
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
