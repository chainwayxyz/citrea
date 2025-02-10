use std::collections::BTreeMap;

use borsh::BorshDeserialize;
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::{BatchProofMethodId, DaDataLightClient, DaNamespace, DaVerifier};
use sov_rollup_interface::mmr::{MMRChunk, MMRGuest, Wtxid};
use sov_rollup_interface::zk::batch_proof::output::v1::BatchProofCircuitOutputV1;
use sov_rollup_interface::zk::batch_proof::output::v2::BatchProofCircuitOutputV2;
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::{
    BatchProofInfo, LightClientCircuitOutput,
};
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;

use crate::utils::{collect_unchained_outputs, recursive_match_state_roots};

type CircuitError = &'static str;

#[derive(Debug)]
pub enum LightClientVerificationError<DaV: DaVerifier> {
    DaTxsCouldntBeVerified(DaV::Error),
    HeaderChainVerificationFailed(DaV::Error),
    InvalidPreviousLightClientProof,
}

// L2 activation height of the fork, and the batch proof method ID
type InitialBatchProofMethodIds = Vec<(u64, [u32; 8])>;

pub fn run_circuit<DaV: DaVerifier, G: ZkvmGuest>(
    da_verifier: DaV,
    input: LightClientCircuitInput<DaV::Spec>,
    l2_genesis_root: [u8; 32],
    initial_batch_proof_method_ids: InitialBatchProofMethodIds,
    batch_prover_da_public_key: &[u8],
    method_id_upgrade_authority_da_public_key: &[u8],
    network: Network,
) -> Result<LightClientCircuitOutput, LightClientVerificationError<DaV>> {
    // Extract previous light client proof output
    let previous_light_client_proof_output =
        if let Some(journal) = input.previous_light_client_proof_journal {
            let prev_output = G::verify_and_deserialize_output::<LightClientCircuitOutput>(
                &journal,
                &input.light_client_proof_method_id.into(),
            )
            .map_err(|_| LightClientVerificationError::<DaV>::InvalidPreviousLightClientProof)?;
            // Ensure method IDs match
            assert_eq!(
                input.light_client_proof_method_id,
                prev_output.light_client_proof_method_id,
            );
            Some(prev_output)
        } else {
            None
        };

    let mut batch_proof_method_ids = previous_light_client_proof_output
        .as_ref()
        .map_or(initial_batch_proof_method_ids, |o| {
            o.batch_proof_method_ids.clone()
        });

    let new_da_state = da_verifier
        .verify_header_chain(
            previous_light_client_proof_output
                .as_ref()
                .map(|output| &output.latest_da_state),
            &input.da_block_header,
            network,
        )
        .map_err(|err| LightClientVerificationError::HeaderChainVerificationFailed(err))?;

    // Verify data from da
    let da_txs = da_verifier
        .verify_transactions(
            &input.da_block_header,
            input.inclusion_proof,
            input.completeness_proof,
            DaNamespace::ToLightClientProver,
        )
        .map_err(|err| LightClientVerificationError::DaTxsCouldntBeVerified(err))?;

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

    let mut in_memory_chunks: BTreeMap<Wtxid, Vec<u8>> = Default::default();
    let mut mmr_hints = input.mmr_hints;

    // index only incremented on processing of a complete or aggregate DA tx
    let mut current_proof_index = 0u32;
    let mut expected_to_fail_hints = input.expected_to_fail_hint.into_iter().peekable();
    // Parse the batch proof da data
    'blob_loop: for blob in da_txs {
        let Ok(data) = DaDataLightClient::try_from_slice(blob.full_data()) else {
            println!("Unparseable blob in da_data, wtxid={:?}", blob.wtxid());
            continue;
        };

        match data {
            // No need to check sender for chunk
            DaDataLightClient::Chunk(chunk) => {
                println!("Found chunk");
                in_memory_chunks.insert(blob.wtxid().expect("Chunk should have a wtxid"), chunk);
            }
            DaDataLightClient::Complete(proof) => {
                println!("Found complete proof");
                if blob.sender().as_ref() != batch_prover_da_public_key {
                    println!(
                        "Complete proof sender is not batch prover, wtxid={:?}",
                        blob.wtxid()
                    );
                    continue;
                }

                let expected_to_fail = expected_to_fail_hints
                    .next_if(|&x| x == current_proof_index)
                    .is_some();
                println!("Complete proof expected to fail: {}", expected_to_fail);
                match process_complete_proof::<G>(
                    &proof,
                    &batch_proof_method_ids,
                    last_l2_height,
                    &mut initial_to_final,
                    expected_to_fail,
                ) {
                    Ok(()) => current_proof_index += 1,
                    Err(e) => println!("Error processing complete proof: {e}"),
                }
            }
            DaDataLightClient::Aggregate(_, wtxids) => {
                println!("Found aggregate proof");
                if blob.sender().as_ref() != batch_prover_da_public_key {
                    println!(
                        "Aggregate proof sender is not batch prover, wtxid={:?}",
                        blob.wtxid()
                    );
                    continue;
                }

                // Ensure that aggregate has all the needed chunks.
                // We can recreate iterator here on every aggregate, because when recreating
                // the complete proof, we pop the used hints from the mmr_hints.
                let mut mmr_hints_iter = mmr_hints.iter();
                let mut in_memory_chunk_count = 0;
                for wtxid in &wtxids {
                    if in_memory_chunks.contains_key(wtxid) {
                        in_memory_chunk_count += 1;
                        continue;
                    }

                    let hint = mmr_hints_iter.next();
                    if hint.is_none() || hint.unwrap().0.wtxid != *wtxid {
                        println!("Missing mmr hint, unprovable aggregate {:?}", blob.wtxid());
                        continue 'blob_loop;
                    }
                }

                println!(
                    "Aggregate has all needed chunks, {} from current block, {} from previous blocks",
                    in_memory_chunk_count,
                    wtxids.len() - in_memory_chunk_count,
                );

                let mut complete_proof = vec![];
                // Used for re-adding chunks back in case of failure
                let mut used_chunk_ptrs = Vec::with_capacity(in_memory_chunk_count);
                for wtxid in wtxids {
                    if let Some(chunk) = in_memory_chunks.remove(&wtxid) {
                        used_chunk_ptrs.push((complete_proof.len(), chunk.len(), wtxid));
                        complete_proof.extend(chunk);
                    } else {
                        let (chunk, proof) = mmr_hints.pop_front().expect("Already checked");

                        if mmr_guest.verify_proof(&chunk, &proof) {
                            complete_proof.extend(chunk.body);
                        } else {
                            panic!("Failed to verify MMR proof for hint");
                        }
                    }
                }

                let reinsert_used_chunks = || {
                    for (idx, size, wtxid) in used_chunk_ptrs {
                        let chunk = complete_proof[idx..idx + size].to_vec();
                        in_memory_chunks.insert(wtxid, chunk);
                    }
                };

                let Ok(complete_proof) = da_verifier.decompress_chunks(&complete_proof) else {
                    println!("Failed to decompress and deserialize completed chunks");
                    reinsert_used_chunks();
                    continue;
                };

                let expected_to_fail = expected_to_fail_hints
                    .next_if(|&x| x == current_proof_index)
                    .is_some();
                println!("Aggregate proof expected to fail: {}", expected_to_fail);
                match process_complete_proof::<G>(
                    &complete_proof,
                    &batch_proof_method_ids,
                    last_l2_height,
                    &mut initial_to_final,
                    expected_to_fail,
                ) {
                    Ok(()) => current_proof_index += 1,
                    // serialization or duplicate proof error
                    Err(e) => {
                        reinsert_used_chunks();
                        println!("Error processing aggregated proof: {e}");
                    }
                }
            }
            DaDataLightClient::BatchProofMethodId(BatchProofMethodId {
                method_id,
                activation_l2_height,
            }) => {
                println!("Found batch proof method id");
                if blob.sender().as_ref() != method_id_upgrade_authority_da_public_key {
                    println!(
                        "Batch proof method id sender is not upgrade authority, wtxid={:?}",
                        blob.wtxid()
                    );
                    continue;
                }

                let last_activation_height = batch_proof_method_ids
                    .last()
                    .expect("Should be at least one")
                    .0;

                if activation_l2_height > last_activation_height {
                    batch_proof_method_ids.push((activation_l2_height, method_id));
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

    if !in_memory_chunks.is_empty() {
        println!("Adding {} more chunks to mmr", in_memory_chunks.len());
        for (wtxid, chunk) in in_memory_chunks {
            mmr_guest.append(MMRChunk::new(wtxid, chunk));
        }
    }

    Ok(LightClientCircuitOutput {
        state_root: last_state_root,
        light_client_proof_method_id: input.light_client_proof_method_id,
        latest_da_state: new_da_state,
        unchained_batch_proofs_info: unchained_outputs,
        last_l2_height,
        batch_proof_method_ids,
        mmr_guest,
    })
}

fn process_complete_proof<G: ZkvmGuest>(
    proof: &[u8],
    batch_proof_method_ids: &InitialBatchProofMethodIds,
    last_l2_height: u64,
    initial_to_final: &mut std::collections::BTreeMap<[u8; 32], ([u8; 32], u64)>,
    expected_to_fail: bool,
) -> Result<(), CircuitError> {
    let Ok(journal) = G::extract_raw_output(proof) else {
        return Err("Failed to extract output from proof");
    };

    let (
        batch_proof_output_initial_state_root,
        batch_proof_output_final_state_root,
        batch_proof_output_last_l2_height,
    ) = if let Ok(output) = G::deserialize_output::<BatchProofCircuitOutputV2>(&journal) {
        (
            output.initial_state_root,
            output.final_state_root,
            output.last_l2_height,
        )
    } else if let Ok(output) = G::deserialize_output::<BatchProofCircuitOutputV1>(&journal) {
        (output.initial_state_root, output.final_state_root, 0)
    } else {
        return Err("Failed to parse proof");
    };

    // Do not add if last l2 height is smaller or equal to previous output
    // This is to defend against replay attacks, for example if somehow there is the script of batch proof 1 we do not need to go through it again
    if batch_proof_output_last_l2_height <= last_l2_height && last_l2_height != 0 {
        return Err("Last L2 height is less than proof's last l2 height");
    }

    let batch_proof_method_id = if batch_proof_method_ids.len() == 1 {
        batch_proof_method_ids[0].1
    } else {
        let idx = match batch_proof_method_ids
            // Returns err and the index to be inserted, which is the index of the first element greater than the key
            // That is why we need to subtract 1 to get the last element smaller than the key
            .binary_search_by_key(&batch_proof_output_last_l2_height, |(height, _)| *height)
        {
            Ok(idx) => idx,
            Err(idx) => idx.saturating_sub(1),
        };
        batch_proof_method_ids[idx].1
    };

    println!("Using batch proof method id {:?}", batch_proof_method_id);

    if expected_to_fail {
        // if index is in the expected to fail hints, then it should fail
        G::verify_expected_to_fail(proof, &batch_proof_method_id.into())
            .expect_err("Proof hinted to fail passed");
    } else {
        // if index is not in the expected to fail hints, then it should pass
        G::verify(&journal, &batch_proof_method_id.into()).expect("Proof hinted to pass failed");
        recursive_match_state_roots(
            initial_to_final,
            &BatchProofInfo::new(
                batch_proof_output_initial_state_root,
                batch_proof_output_final_state_root,
                batch_proof_output_last_l2_height,
            ),
        );
    }

    Ok(())
}
