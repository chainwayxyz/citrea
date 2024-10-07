use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use anyhow::anyhow;
use borsh::de::BorshDeserialize;
use jsonrpsee::core::DeserializeOwned;
use sov_db::ledger_db::{ProverLedgerOps, SharedLedgerOps};
use sov_db::schema::types::BatchNumber;
use sov_rollup_interface::da::{
    BlobReaderTrait, BlockHeaderTrait, DaDataBatchProof, DaSpec, SequencerCommitment,
};
use sov_rollup_interface::rpc::SoftConfirmationStatus;
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::soft_confirmation::SignedSoftConfirmation;
use sov_rollup_interface::stf::StateDiff;
use tokio::sync::Mutex;

use crate::cache::L1BlockCache;
use crate::da::get_da_block_at_height;

type CommitmentStateTransitionData<Witness, Da> = (
    VecDeque<Vec<Witness>>,
    VecDeque<Vec<SignedSoftConfirmation>>,
    VecDeque<Vec<<<Da as DaService>::Spec as DaSpec>::BlockHeader>>,
);

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

pub fn extract_sequencer_commitments<Da: DaService>(
    sequencer_da_pub_key: &[u8],
    l1_block_hash: [u8; 32],
    da_data: &mut [<<Da as DaService>::Spec as DaSpec>::BlobTransaction],
) -> Vec<SequencerCommitment> {
    let mut sequencer_commitments = vec![];
    // if we don't do this, the zk circuit can't read the sequencer commitments
    da_data.iter_mut().for_each(|blob| {
        blob.full_data();
    });
    da_data.iter_mut().for_each(|tx| {
        let data = DaDataBatchProof::try_from_slice(tx.full_data());
        // Check for commitment
        if tx.sender().as_ref() == sequencer_da_pub_key {
            if let Ok(DaDataBatchProof::SequencerCommitment(seq_com)) = data {
                sequencer_commitments.push(seq_com);
            } else {
                tracing::warn!(
                    "Found broken DA data in block 0x{}: {:?}",
                    hex::encode(l1_block_hash),
                    data
                );
            }
        }
    });
    sequencer_commitments
}

pub async fn get_state_transition_data_from_commitments<
    Da: DaService,
    DB: ProverLedgerOps,
    Witness: DeserializeOwned,
>(
    sequencer_commitments: &[SequencerCommitment],
    da_service: &Arc<Da>,
    ledger_db: &DB,
    l1_block_cache: &Arc<Mutex<L1BlockCache<Da>>>,
) -> Result<CommitmentStateTransitionData<Witness, Da>, anyhow::Error> {
    let mut state_transition_witnesses: VecDeque<Vec<Witness>> = VecDeque::new();
    let mut soft_confirmations: VecDeque<Vec<SignedSoftConfirmation>> = VecDeque::new();
    let mut da_block_headers_of_soft_confirmations: VecDeque<
        Vec<<<Da as DaService>::Spec as DaSpec>::BlockHeader>,
    > = VecDeque::new();
    for sequencer_commitment in sequencer_commitments.to_owned().iter() {
        // get the l2 height ranges of each seq_commitments
        let mut witnesses = vec![];
        let start_l2 = sequencer_commitment.l2_start_block_number;
        let end_l2 = sequencer_commitment.l2_end_block_number;
        let soft_confirmations_in_commitment = match ledger_db
            .get_soft_confirmation_range(&(BatchNumber(start_l2)..=BatchNumber(end_l2)))
        {
            Ok(soft_confirmations) => soft_confirmations,
            Err(e) => {
                return Err(anyhow!(
                    "Failed to get soft confirmations from the ledger db: {}",
                    e
                ));
            }
        };
        let mut commitment_soft_confirmations = vec![];
        let mut da_block_headers_to_push: Vec<<<Da as DaService>::Spec as DaSpec>::BlockHeader> =
            vec![];
        for soft_confirmation in soft_confirmations_in_commitment {
            if da_block_headers_to_push.is_empty()
                || da_block_headers_to_push.last().unwrap().height()
                    != soft_confirmation.da_slot_height
            {
                let filtered_block = match get_da_block_at_height(
                    da_service,
                    soft_confirmation.da_slot_height,
                    l1_block_cache.clone(),
                )
                .await
                {
                    Ok(block) => block,
                    Err(_) => {
                        return Err(anyhow!(
                            "Error while fetching DA block at height: {}",
                            soft_confirmation.da_slot_height
                        ));
                    }
                };
                da_block_headers_to_push.push(filtered_block.header().clone());
            }
            let signed_soft_confirmation: SignedSoftConfirmation = soft_confirmation.clone().into();
            commitment_soft_confirmations.push(signed_soft_confirmation.clone());
        }
        soft_confirmations.push_back(commitment_soft_confirmations);

        da_block_headers_of_soft_confirmations.push_back(da_block_headers_to_push);
        for l2_height in
            sequencer_commitment.l2_start_block_number..=sequencer_commitment.l2_end_block_number
        {
            let witness = match ledger_db.get_l2_witness::<Witness>(l2_height) {
                Ok(witness) => witness,
                Err(e) => return Err(anyhow!("Failed to get witness from the ledger db: {}", e)),
            };

            witnesses.push(witness.expect("A witness must be present"));
        }
        state_transition_witnesses.push_back(witnesses);
    }
    Ok((
        state_transition_witnesses,
        soft_confirmations,
        da_block_headers_of_soft_confirmations,
    ))
}
