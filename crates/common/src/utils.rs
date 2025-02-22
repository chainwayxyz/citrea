use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context as _;
use citrea_primitives::EMPTY_TX_ROOT;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::SharedLedgerOps;
use sov_db::schema::types::SoftConfirmationNumber;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{Context, Spec};
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::digest::Digest;
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::StateDiff;

pub fn merge_state_diffs(old_diff: StateDiff, new_diff: StateDiff) -> StateDiff {
    let mut new_diff_map: HashMap<Arc<[u8]>, Option<Arc<[u8]>>> = HashMap::from_iter(old_diff);

    new_diff_map.extend(new_diff);
    new_diff_map.into_iter().collect()
}

/// Remove proven commitments using the end block number of the L2 range.
/// This is basically filtering out proven soft confirmations.
pub fn filter_out_proven_commitments<DB: SharedLedgerOps>(
    ledger_db: &DB,
    sequencer_commitments: &[SequencerCommitment],
) -> anyhow::Result<(Vec<SequencerCommitment>, Vec<usize>)> {
    filter_out_commitments_by_status(
        ledger_db,
        sequencer_commitments,
        SoftConfirmationStatus::Proven,
    )
}

fn filter_out_commitments_by_status<DB: SharedLedgerOps>(
    ledger_db: &DB,
    sequencer_commitments: &[SequencerCommitment],
    exclude_status: SoftConfirmationStatus,
) -> anyhow::Result<(Vec<SequencerCommitment>, Vec<usize>)> {
    let mut skipped_commitments = vec![];
    let mut filtered = vec![];
    let mut visited_l2_ranges = HashSet::new();
    for (index, sequencer_commitment) in sequencer_commitments.iter().enumerate() {
        // Handle commitments which have the same L2 range
        let current_range = (
            sequencer_commitment.l2_start_block_number,
            sequencer_commitment.l2_end_block_number,
        );
        if visited_l2_ranges.contains(&current_range) {
            continue;
        }
        visited_l2_ranges.insert(current_range);

        // Check if the commitment was previously finalized.
        let Some(status) = ledger_db.get_soft_confirmation_status(SoftConfirmationNumber(
            sequencer_commitment.l2_end_block_number,
        ))?
        else {
            filtered.push(sequencer_commitment.clone());
            continue;
        };

        if status != exclude_status {
            filtered.push(sequencer_commitment.clone());
        } else {
            skipped_commitments.push(index);
        }
    }

    Ok((filtered, skipped_commitments))
}

pub fn check_l2_block_exists<DB: SharedLedgerOps>(ledger_db: &DB, l2_height: u64) -> bool {
    let Some(head_l2_height) = ledger_db
        .get_head_soft_confirmation_height()
        .expect("Ledger db read must not fail")
    else {
        return false;
    };

    head_l2_height >= l2_height
}

pub fn compute_tx_hashes<C: Context>(txs: &[Transaction], current_spec: SpecId) -> Vec<[u8; 32]> {
    if current_spec >= SpecId::Kumquat {
        txs.iter()
            .map(|tx| tx.compute_digest::<<C as Spec>::Hasher>().into())
            .collect()
    } else {
        txs.iter()
            .map(|tx| {
                let serialized = borsh::to_vec(tx).expect("Tx serialization shouldn't fail");
                <C as Spec>::Hasher::digest(&serialized).into()
            })
            .collect()
    }
}

pub fn compute_tx_merkle_root(tx_hashes: &[[u8; 32]]) -> anyhow::Result<[u8; 32]> {
    if tx_hashes.is_empty() {
        return Ok(EMPTY_TX_ROOT);
    }

    MerkleTree::<Sha256>::from_leaves(tx_hashes)
        .root()
        .context("Couldn't compute merkle root")
}
