use std::collections::{BTreeMap, BTreeSet};
use std::vec;

use anyhow::anyhow;
use borsh::BorshDeserialize;
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::{DaDataLightClient, DaNamespace, DaVerifier};
use sov_rollup_interface::mmr::{MMRGuest, MMRNode};
use sov_rollup_interface::zk::{
    BatchProofCircuitOutput, BatchProofInfo, LightClientCircuitInput, LightClientCircuitOutput,
    ZkvmGuest,
};

use crate::utils::{collect_unchained_outputs, recursive_match_state_roots};

#[derive(Debug)]
pub enum LightClientVerificationError {
    DaTxsCouldntBeVerified,
    HeaderChainVerificationFailed,
    InvalidPreviousLightClientProof,
}

pub fn run_circuit<DaV: DaVerifier, G: ZkvmGuest>(
    da_verifier: DaV,
    input: LightClientCircuitInput<DaV::Spec>,
    l2_genesis_root: [u8; 32],
    batch_proof_method_id: [u32; 8],
    batch_prover_da_public_key: &[u8],
) -> Result<LightClientCircuitOutput<DaV::Spec>, LightClientVerificationError> {
    // Extract previous light client proof output
    let previous_light_client_proof_output =
        if let Some(journal) = input.previous_light_client_proof_journal {
            let prev_output = G::verify_and_extract_output::<LightClientCircuitOutput<DaV::Spec>>(
                &journal,
                &input.light_client_proof_method_id.into(),
            )
            .map_err(|_| LightClientVerificationError::InvalidPreviousLightClientProof)?;
            // Ensure method IDs match
            assert_eq!(
                input.light_client_proof_method_id,
                prev_output.light_client_proof_method_id,
            );
            Some(prev_output)
        } else {
            None
        };

    let block_updates = da_verifier
        .verify_header_chain(&previous_light_client_proof_output, &input.da_block_header)
        .map_err(|_| LightClientVerificationError::HeaderChainVerificationFailed)?;

    // Verify data from da
    da_verifier
        .verify_transactions(
            &input.da_block_header,
            input.da_data.as_slice(),
            input.inclusion_proof,
            input.completeness_proof,
            DaNamespace::ToLightClientProver,
        )
        .map_err(|_| LightClientVerificationError::DaTxsCouldntBeVerified)?;

    // Mapping from initial state root to final state root and last L2 height
    let mut initial_to_final = BTreeMap::<[u8; 32], ([u8; 32], u64)>::new();

    let (mut last_state_root, mut last_l2_height, mut mmr_guest) =
        previous_light_client_proof_output.as_ref().map_or_else(
            || {
                // if no previous proof, we start from genesis state root
                (l2_genesis_root, 0, MMRGuest::new())
            },
            |prev_journal| {
                (
                    prev_journal.state_root,
                    prev_journal.last_l2_height,
                    prev_journal.mmr_guest.clone(),
                )
            },
        );

    // If we have a previous light client proof, check they can be chained
    // If not, skip for now
    if let Some(previous_output) = &previous_light_client_proof_output {
        for unchained_info in previous_output.unchained_batch_proofs_info.iter() {
            // Add them directly as they are the ones that could not be matched
            initial_to_final.insert(
                unchained_info.initial_state_root,
                (
                    unchained_info.final_state_root,
                    unchained_info.last_l2_height,
                ),
            );
        }
    }

    let mut in_memory_chunks: BTreeMap<[u8; 32], Vec<u8>> = Default::default();
    let mut mmr_hints = input.mmr_hints.clone();

    // TODO: Test for multiple assumptions to see if the env::verify function does automatic matching between the journal and the assumption or do we need to verify them in order?
    // https://github.com/chainwayxyz/citrea/issues/1401
    // Parse the batch proof da data
    for blob in input.da_data {
        if blob.sender().as_ref() == batch_prover_da_public_key {
            let data = DaDataLightClient::try_from_slice(blob.verified_data());

            if let Ok(data) = data {
                match data {
                    DaDataLightClient::Complete(proof) => {
                        let result = process_complete_proof::<DaV, G>(
                            proof,
                            batch_proof_method_id,
                            last_l2_height,
                            &mut initial_to_final,
                        );

                        if result.is_err() {
                            continue;
                        }
                    }
                    DaDataLightClient::Aggregate(_tx_ids, wtx_ids) => {
                        let mut chunks_related = vec![];
                        for wtxid in &wtx_ids {
                            if !in_memory_chunks.contains_key(wtxid) {
                                let (chunk, proof) = mmr_hints.pop_front().unwrap();

                                if !mmr_guest.verify_proof(&chunk, &proof) {
                                    // circuit not provided with enough hints
                                    continue;
                                }

                                chunks_related.push(chunk);
                            } else {
                                in_memory_chunks.remove(wtxid);
                            }
                        }
                        let existing_wtx_ids: BTreeSet<[u8; 32]> =
                            in_memory_chunks.keys().cloned().collect();
                        let aggregate_wtx_ids: BTreeSet<[u8; 32]> =
                            wtx_ids.iter().cloned().collect();

                        // If we have all the chunks, perform verification
                        if aggregate_wtx_ids.is_subset(&existing_wtx_ids) {
                            // Concatenate complete proof
                            let complete_proof = wtx_ids
                                .iter()
                                .filter_map(|k| in_memory_chunks.get(k).cloned())
                                .flatten()
                                .collect::<Vec<_>>();

                            let result = process_complete_proof::<DaV, G>(
                                complete_proof,
                                batch_proof_method_id,
                                last_l2_height,
                                &mut initial_to_final,
                            );

                            if result.is_err() {
                                continue;
                            }

                            for wtx_id in &aggregate_wtx_ids {
                                in_memory_chunks.remove(wtx_id);
                            }
                        }
                    }
                    DaDataLightClient::Chunk(chunk) => {
                        // Store the chunk in memory
                        in_memory_chunks
                            .insert(blob.wtxid().expect("Chunk should have a wtxid"), chunk);
                    }
                }
            }
        }
    }

    // Do recursive matching for previous state root
    recursive_match_state_roots(
        &mut initial_to_final,
        &BatchProofInfo::new(last_state_root, last_state_root, last_l2_height),
    );

    // Now only thing left is the state update if exists and others are unchained
    if let Some((final_root, last_l2)) = initial_to_final.remove(&last_state_root) {
        last_l2_height = last_l2;
        last_state_root = final_root;
    }

    // Collect unchained outputs
    let unchained_outputs = collect_unchained_outputs(&initial_to_final, last_l2_height);

    if in_memory_chunks.len() > 0 {
        for (wtxid, chunk) in in_memory_chunks {
            mmr_guest.append(MMRNode::new(wtxid, chunk));
        }
    }

    Ok(LightClientCircuitOutput {
        state_root: last_state_root,
        light_client_proof_method_id: input.light_client_proof_method_id,
        da_block_hash: block_updates.hash,
        da_block_height: block_updates.height,
        da_total_work: block_updates.total_work,
        da_current_target_bits: block_updates.current_target_bits,
        da_epoch_start_time: block_updates.epoch_start_time,
        da_prev_11_timestamps: block_updates.prev_11_timestamps,
        unchained_batch_proofs_info: unchained_outputs,
        last_l2_height,
        mmr_guest,
    })
}

fn process_complete_proof<DaV: DaVerifier, G: ZkvmGuest>(
    proof: Vec<u8>,
    batch_proof_method_id: [u32; 8],
    last_l2_height: u64,
    initial_to_final: &mut std::collections::BTreeMap<[u8; 32], ([u8; 32], u64)>,
) -> anyhow::Result<()> {
    let journal = G::extract_raw_output(&proof).expect("DaData proofs must be valid");
    // TODO: select output version based on the spec
    let batch_proof_output: BatchProofCircuitOutput<DaV::Spec, [u8; 32]> =
        match G::verify_and_extract_output(&journal, &batch_proof_method_id.into()) {
            Ok(output) => output,
            Err(_) => return Err(anyhow!("Failed to verify proof")),
        };

    // Do not add if last l2 height is smaller or equal to previous output
    // This is to defend against replay attacks, for example if somehow there is the script of batch proof 1 we do not need to go through it again
    if batch_proof_output.last_l2_height <= last_l2_height {
        return Err(anyhow!(
            "Last L2 height is less than proof's last l2 height"
        ));
    }

    recursive_match_state_roots(
        initial_to_final,
        &BatchProofInfo::new(
            batch_proof_output.initial_state_root,
            batch_proof_output.final_state_root,
            batch_proof_output.last_l2_height,
        ),
    );

    Ok(())
}
