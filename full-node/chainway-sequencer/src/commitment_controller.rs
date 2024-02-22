use std::ops::RangeInclusive;

use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::LedgerDB;
use sov_db::schema::types::{BatchNumber, SlotNumber};
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::rpc::LedgerRpcProvider;
use tracing::debug;

#[derive(Clone, Debug)]
pub struct CommitmentInfo {
    /// L2 heights to commit
    pub l2_height_range: RangeInclusive<BatchNumber>,
    /// Respectuflly, the L1 heights to commit. (L2 blocks were created with these L1 blocks.)
    pub l1_height_range: RangeInclusive<BatchNumber>,
    pub l1_start_hash: [u8; 32],
    pub l1_end_hash: [u8; 32],
}

/// Checks if the sequencer should commit
/// Returns none if the commitable L2 block range is shorter than `min_soft_confirmations_per_commitment`
/// Returns `CommitmentInfo` if the sequencer should commit
pub fn get_commitment_info(
    ledger_db: &LedgerDB,
    min_soft_confirmations_per_commitment: u64,
    prev_l1_height: u64,
) -> Option<CommitmentInfo> {
    // first get when the last merkle root of soft confirmations was submitted
    let last_commitment_l1_height = ledger_db
        .get_last_sequencer_commitment_l1_height()
        .expect("Sequencer: Failed to get last sequencer commitment L1 height");

    debug!("Last commitment L1 height: {:?}", last_commitment_l1_height);
    let mut l2_range_to_submit = None;
    let mut _l1_height_range = None;
    // if none then we never submitted a commitment, start from prev_l1_height and go back as far as you can go
    // if there is a height then start from height + 1 and go to prev_l1_height
    match last_commitment_l1_height {
        Some(height) => {
            let mut l1_height = height.0 + 1;

            _l1_height_range = Some((l1_height, l1_height));

            while let Some(l2_height_range) = ledger_db
                .get_l2_range_by_l1_height(SlotNumber(l1_height))
                .expect("Sequencer: Failed to get L1 L2 connection")
            {
                if l2_range_to_submit.is_none() {
                    l2_range_to_submit = Some(l2_height_range);
                } else {
                    l2_range_to_submit = Some((l2_range_to_submit.unwrap().0, l2_height_range.1));
                }

                l1_height += 1;
            }

            _l1_height_range = Some((_l1_height_range.unwrap().0, l1_height - 1));
        }
        None => {
            let mut l1_height = prev_l1_height;

            _l1_height_range = Some((prev_l1_height, prev_l1_height));

            while let Some(l2_height_range) = ledger_db
                .get_l2_range_by_l1_height(SlotNumber(l1_height))
                .expect("Sequencer: Failed to get L1 L2 connection")
            {
                if l2_range_to_submit.is_none() {
                    l2_range_to_submit = Some(l2_height_range);
                } else {
                    l2_range_to_submit = Some((l2_height_range.0, l2_range_to_submit.unwrap().1));
                }

                l1_height -= 1;
            }

            _l1_height_range = Some((l1_height + 1, _l1_height_range.unwrap().1));
        }
    };

    debug!("L2 range to submit: {:?}", l2_range_to_submit);
    debug!("L1 height range: {:?}", _l1_height_range);

    if l2_range_to_submit.is_none()
        || (l2_range_to_submit.unwrap().1 .0 - l2_range_to_submit.unwrap().0 .0 + 1)
            < min_soft_confirmations_per_commitment
    {
        return None;
    }

    let l2_range_to_submit = l2_range_to_submit.unwrap();
    let l1_height_range = _l1_height_range.unwrap();

    let l1_start_hash = ledger_db
        .get_soft_batch_by_number::<()>(l2_range_to_submit.0 .0)
        .expect("Failed to get soft batch")
        .unwrap()
        .da_slot_hash;

    let l1_end_hash = ledger_db
        .get_soft_batch_by_number::<()>(l2_range_to_submit.1 .0)
        .expect("Failed to get soft batch")
        .unwrap()
        .da_slot_hash;

    debug!("L1 start hash: {:?}", l1_start_hash);
    debug!("L1 end hash: {:?}", l1_end_hash);

    Some(CommitmentInfo {
        l2_height_range: l2_range_to_submit.0..=l2_range_to_submit.1,
        l1_height_range: BatchNumber(l1_height_range.0)..=BatchNumber(l1_height_range.1),
        l1_start_hash,
        l1_end_hash,
    })
}

pub fn get_commitment(
    commitment_info: CommitmentInfo,
    soft_confirmation_hashes: Vec<[u8; 32]>,
) -> SequencerCommitment {
    // sanity check
    assert_eq!(
        commitment_info.l2_height_range.end().0 - commitment_info.l2_height_range.start().0 + 1u64,
        soft_confirmation_hashes.len() as u64,
        "Sequencer: Soft confirmation hashes length does not match the commitment info"
    );

    // build merkle tree over soft confirmations
    let merkle_root = MerkleTree::<Sha256>::from_leaves(soft_confirmation_hashes.as_slice())
        .root()
        .expect("Couldn't compute merkle root");
    SequencerCommitment {
        merkle_root,
        l1_start_block_hash: commitment_info.l1_start_hash,
        l1_end_block_hash: commitment_info.l1_end_hash,
    }
}
