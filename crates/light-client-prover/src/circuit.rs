use std::collections::{BTreeMap, BTreeSet};
use std::vec;

use anyhow::anyhow;
use borsh::BorshDeserialize;
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::{BatchProofMethodId, DaDataLightClient, DaNamespace, DaVerifier};
use sov_rollup_interface::mmr::{MMRGuest, MMRNode};
use sov_rollup_interface::zk::{
    BatchProofCircuitOutput, BatchProofInfo, LightClientCircuitInput, LightClientCircuitOutput,
    OldBatchProofCircuitOutput, ZkvmGuest,
};
use sov_rollup_interface::Network;

use crate::utils::{collect_unchained_outputs, recursive_match_state_roots};

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
    da_verifier
        .verify_transactions(
            &input.da_block_header,
            input.da_data.as_slice(),
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

    let mut in_memory_chunks: BTreeMap<[u8; 32], Vec<u8>> = Default::default();
    let mut mmr_hints = input.mmr_hints.clone();

    for blob in input.da_data {
        if blob.sender().as_ref() == batch_prover_da_public_key {
            let data = DaDataLightClient::try_from_slice(blob.verified_data());

            if let Ok(data) = data {
                match data {
                    DaDataLightClient::Complete(proof) => {
                        let result = process_complete_proof::<DaV, G>(
                            proof,
                            &batch_proof_method_ids,
                            last_l2_height,
                            &mut initial_to_final,
                        );

                        if let Err(e) = result {
                            println!("Error in light client guest: {:?}", e);
                            continue;
                        }
                    }
                    DaDataLightClient::Aggregate(_tx_ids, wtx_ids) => {
                        let mut aggregate_chunks = vec![];
                        'wtxids_loop: for wtxid in &wtx_ids {
                            // If the wtxid belongs to a chunk that we've seen in a previous L1 block,
                            // We use the hints to verify the existence of the chunk.
                            if in_memory_chunks.contains_key(wtxid) {
                                let chunk = in_memory_chunks
                                    .get(wtxid)
                                    .expect("Chunk with wtxid should exist at this point")
                                    .to_vec();
                                aggregate_chunks.push(MMRNode::new(*wtxid, chunk));
                                in_memory_chunks.remove(wtxid);
                            } else {
                                while let Some((chunk, proof)) = mmr_hints.pop_front() {
                                    if !mmr_guest.verify_proof(&chunk, &proof) {
                                        // circuit not provided with enough hints
                                        continue 'wtxids_loop;
                                    }

                                    aggregate_chunks.push(chunk);
                                }
                            }
                        }

                        let existing_wtx_ids: BTreeSet<[u8; 32]> =
                            aggregate_chunks.iter().map(|c| c.wtxid).collect();
                        let aggregate_wtx_ids: BTreeSet<[u8; 32]> =
                            wtx_ids.iter().cloned().collect();

                        // Make sure we have all the chunks, perform verification
                        if aggregate_wtx_ids.is_subset(&existing_wtx_ids) {
                            // Concatenate complete proof
                            let complete_proof = aggregate_chunks
                                .iter()
                                .flat_map(|n| n.body.clone())
                                .collect::<Vec<_>>();

                            let result = process_complete_proof::<DaV, G>(
                                complete_proof,
                                &batch_proof_method_ids,
                                last_l2_height,
                                &mut initial_to_final,
                            );

                            if let Err(e) = result {
                                println!("Error in light client guest: {:?}", e);
                                continue;
                            }
                        }
                    }
                    DaDataLightClient::Chunk(chunk) => {
                        // Store the chunk in memory
                        in_memory_chunks
                            .insert(blob.wtxid().expect("Chunk should have a wtxid"), chunk);
                    }
                    DaDataLightClient::BatchProofMethodId(_) => {} // if coming from batch prover, ignore
                }
            }
        } else if blob.sender().as_ref() == method_id_upgrade_authority_da_public_key {
            let data = DaDataLightClient::try_from_slice(blob.verified_data());

            if let Ok(DaDataLightClient::BatchProofMethodId(BatchProofMethodId {
                method_id,
                activation_l2_height,
            })) = data
            {
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

    for (wtxid, chunk) in in_memory_chunks {
        mmr_guest.append(MMRNode::new(wtxid, chunk));
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

fn process_complete_proof<DaV: DaVerifier, G: ZkvmGuest>(
    proof: Vec<u8>,
    batch_proof_method_ids: &InitialBatchProofMethodIds,
    last_l2_height: u64,
    initial_to_final: &mut std::collections::BTreeMap<[u8; 32], ([u8; 32], u64)>,
) -> anyhow::Result<()> {
    let journal = G::extract_raw_output(&proof).expect("DaData proofs must be valid");

    let (
        batch_proof_output_initial_state_root,
        batch_proof_output_final_state_root,
        batch_proof_output_last_l2_height,
    ) = if let Ok(output) =
        G::deserialize_output::<BatchProofCircuitOutput<DaV::Spec, [u8; 32]>>(&journal)
    {
        (
            output.initial_state_root,
            output.final_state_root,
            output.last_l2_height,
        )
    } else if let Ok(output) =
        G::deserialize_output::<OldBatchProofCircuitOutput<DaV::Spec, [u8; 32]>>(&journal)
    {
        (output.initial_state_root, output.final_state_root, 0)
    } else {
        return Err(anyhow!("Failed to parse proof"));
    };

    // Do not add if last l2 height is smaller or equal to previous output
    // This is to defend against replay attacks, for example if somehow there is the script of batch proof 1 we do not need to go through it again
    if batch_proof_output_last_l2_height <= last_l2_height {
        return Err(anyhow!(
            "Last L2 height is less than proof's last l2 height"
        ));
    }

    let batch_proof_method_id = if batch_proof_method_ids.len() == 1 {
        // Check if last l2 height is greater than or equal to the only batch proof method id activation height
        if batch_proof_output_last_l2_height >= batch_proof_method_ids[0].0 {
            batch_proof_method_ids[0].1
        } else {
            // If not continue to the next blob
            return Ok(());
        }
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

    if G::verify(&journal, &batch_proof_method_id.into()).is_err() {
        // if the batch proof is invalid, continue to the next blob
        return Err(anyhow!("Failed to verify proof"));
    }

    recursive_match_state_roots(
        initial_to_final,
        &BatchProofInfo::new(
            batch_proof_output_initial_state_root,
            batch_proof_output_final_state_root,
            batch_proof_output_last_l2_height,
        ),
    );

    Ok(())
}
