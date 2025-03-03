use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use alloy_sol_types::SolCall;
use anyhow::{anyhow, Context as _};
use borsh::BorshDeserialize;
use citrea_evm::system_contracts::BitcoinLightClientContract;
use citrea_evm::{CallMessage as EvmCallMessage, SYSTEM_SIGNER};
use citrea_primitives::EMPTY_TX_ROOT;
use reth_primitives::TransactionSignedEcRecovered;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::SharedLedgerOps;
use sov_db::schema::types::SoftConfirmationNumber;
use sov_modules_api::transaction::Transaction;
use sov_modules_api::{Context, DaSpec, Spec};
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::digest::Digest;
use sov_rollup_interface::rpc::{SoftConfirmationResponse, SoftConfirmationStatus};
use sov_rollup_interface::services::da::DaService;
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

async fn update_short_header_proof_from_sys_tx<Da: DaService, DB: SharedLedgerOps>(
    tx: &TransactionSignedEcRecovered,
    ledger_db: &DB,
    da_service: Arc<Da>,
) -> anyhow::Result<()> {
    let function_selector: [u8; 4] = tx.input()[0..4].try_into()?;

    if function_selector == BitcoinLightClientContract::setBlockInfoCall::SELECTOR {
        let l1_block_hash: [u8; 32] = tx.input()[4..36].try_into()?;
        // Check if shp exists for this l1 block hash
        if ledger_db
            .get_short_header_proof_by_l1_hash(&l1_block_hash)?
            .is_some()
        {
            return Ok(());
        }
        let da_block = da_service
            .get_block_by_hash(l1_block_hash.into())
            .await
            .map_err(|e| anyhow!(e))?;
        let short_header_proof: <<Da as DaService>::Spec as DaSpec>::ShortHeaderProof =
            Da::block_to_short_header_proof(da_block);
        ledger_db
            .put_short_header_proof_by_l1_hash(
                &l1_block_hash,
                borsh::to_vec(&short_header_proof).expect("Should serialize short header proof"),
            )
            .expect("Should save short header proof to ledger db");
    }

    Ok(())
}

/// This does not check for misplaced sys txs etc. but they will be rejected by the stf if they are misplaced when the transactions are run
pub async fn decode_sov_tx_and_update_short_header_proofs<Da: DaService, DB: SharedLedgerOps>(
    soft_confirmation_response: &SoftConfirmationResponse,
    ledger_db: &DB,
    da_service: Arc<Da>,
) -> anyhow::Result<()> {
    if let Some(txs) = &soft_confirmation_response.txs {
        for tx in txs {
            let tx = &tx.tx;
            let tx = Transaction::try_from_slice(tx).expect("Should deserialize transaction");
            let runtime_msg = tx.runtime_msg();
            if runtime_msg[0] == 1 {
                // This is evm call message
                let evm_call_message =
                    EvmCallMessage::try_from_slice(&runtime_msg[1..]).expect("Should be the tx");
                let evm_txs = evm_call_message.txs;
                for tx in evm_txs {
                    let tx = TransactionSignedEcRecovered::try_from(tx)
                        .expect("Should deserialize evm transaction");
                    if tx.signer() == SYSTEM_SIGNER {
                        update_short_header_proof_from_sys_tx(&tx, ledger_db, da_service.clone())
                            .await?;
                    }
                }
            }
        }
    }
    Ok(())
}
