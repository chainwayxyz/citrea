use std::collections::{HashMap, HashSet};

use sov_db::ledger_db::SharedLedgerOps;
use sov_db::schema::types::BatchNumber;
use sov_modules_api::{Context, Spec};
use sov_rollup_interface::da::{DaSpec, SequencerCommitment};
use sov_rollup_interface::digest::Digest;
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmation;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::{SoftConfirmationReceipt, StateDiff, TransactionDigest};
use tokio::signal;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;

pub fn merge_state_diffs(old_diff: StateDiff, new_diff: StateDiff) -> StateDiff {
    let mut new_diff_map = HashMap::<Vec<u8>, Option<Vec<u8>>>::from_iter(old_diff);

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
        let Some(status) = ledger_db
            .get_soft_confirmation_status(BatchNumber(sequencer_commitment.l2_end_block_number))?
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

pub fn check_l2_range_exists<DB: SharedLedgerOps>(
    ledger_db: &DB,
    first_l2_height_of_l1: u64,
    last_l2_height_of_l1: u64,
) -> bool {
    if let Ok(range) = ledger_db.get_soft_confirmation_range(
        &(BatchNumber(first_l2_height_of_l1)..=BatchNumber(last_l2_height_of_l1)),
    ) {
        if (range.len() as u64) >= (last_l2_height_of_l1 - first_l2_height_of_l1 + 1) {
            return true;
        }
    }
    false
}

pub fn soft_confirmation_to_receipt<C: Context, Tx: TransactionDigest + Clone, DS: DaSpec>(
    soft_confirmation: SignedSoftConfirmation<'_, Tx>,
    current_spec: SpecId,
) -> SoftConfirmationReceipt<DS> {
    let tx_hashes = if current_spec >= SpecId::Fork1 {
        soft_confirmation
            .txs()
            .iter()
            .map(|tx| tx.compute_digest::<<C as Spec>::Hasher>().into())
            .collect()
    } else {
        soft_confirmation
            .blobs()
            .iter()
            .map(|raw_tx| <C as Spec>::Hasher::digest(raw_tx).into())
            .collect()
    };

    SoftConfirmationReceipt {
        l2_height: soft_confirmation.l2_height(),
        hash: soft_confirmation.hash(),
        prev_hash: soft_confirmation.prev_hash(),
        da_slot_height: soft_confirmation.da_slot_height(),
        da_slot_hash: soft_confirmation.da_slot_hash().into(),
        da_slot_txs_commitment: soft_confirmation.da_slot_txs_commitment().into(),
        l1_fee_rate: soft_confirmation.l1_fee_rate(),
        tx_hashes,
        deposit_data: soft_confirmation.deposit_data().to_vec(),
        timestamp: soft_confirmation.timestamp(),
        soft_confirmation_signature: soft_confirmation.signature().to_vec(),
        pub_key: soft_confirmation.pub_key().to_vec(),
    }
}
pub async fn create_shutdown_signal() -> tokio::sync::mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel(1);

    tokio::spawn(async move {
        let term_signal = signal(SignalKind::terminate()).ok();

        if let Some(mut term_signal) = term_signal {
            tokio::select! {
                _ = signal::ctrl_c() => {
                    let _ = tx.send(()).await;
                }
                _ = term_signal.recv() => {
                    let _ = tx.send(()).await;
                }
            }
        } else {
            let _ = signal::ctrl_c().await;
            let _ = tx.send(()).await;
        }
    });

    rx
}
