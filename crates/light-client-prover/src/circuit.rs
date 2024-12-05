use borsh::BorshDeserialize;
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::{DaDataLightClient, DaNamespace, DaVerifier};
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
    guest: &G,
) -> Result<LightClientCircuitOutput<DaV::Spec>, LightClientVerificationError> {
    let input: LightClientCircuitInput<DaV::Spec> = guest.read_from_host();

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
    let mut initial_to_final = std::collections::BTreeMap::<[u8; 32], ([u8; 32], u64)>::new();

    let (mut last_state_root, mut last_l2_height, l2_genesis_state_root) =
        previous_light_client_proof_output.as_ref().map_or_else(
            || {
                let r = input
                    .l2_genesis_state_root
                    .expect("if no preious proof, genesis must exist");
                (r, 0, r)
            },
            |prev_journal| {
                (
                    prev_journal.state_root,
                    prev_journal.last_l2_height,
                    prev_journal.l2_genesis_state_root,
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
    // TODO: Test for multiple assumptions to see if the env::verify function does automatic matching between the journal and the assumption or do we need to verify them in order?
    // https://github.com/chainwayxyz/citrea/issues/1401
    let batch_proof_method_id = input.batch_proof_method_id;
    // Parse the batch proof da data
    for blob in input.da_data {
        if blob.sender().as_ref() == input.batch_prover_da_pub_key {
            let data = DaDataLightClient::try_from_slice(blob.verified_data());

            if let Ok(data) = data {
                match data {
                    DaDataLightClient::Complete(proof) => {
                        let journal =
                            G::extract_raw_output(&proof).expect("DaData proofs must be valid");
                        // TODO: select output version based on the spec
                        let batch_proof_output: BatchProofCircuitOutput<DaV::Spec, [u8; 32]> =
                            match G::verify_and_extract_output(
                                &journal,
                                &batch_proof_method_id.into(),
                            ) {
                                Ok(output) => output,
                                Err(_) => continue,
                            };

                        // Do not add if last l2 height is smaller or equal to previous output
                        // This is to defend against replay attacks, for example if somehow there is the script of batch proof 1 we do not need to go through it again
                        if batch_proof_output.last_l2_height <= last_l2_height {
                            continue;
                        }

                        recursive_match_state_roots(
                            &mut initial_to_final,
                            &BatchProofInfo::new(
                                batch_proof_output.initial_state_root,
                                batch_proof_output.final_state_root,
                                batch_proof_output.last_l2_height,
                            ),
                        );
                    }
                    DaDataLightClient::Aggregate(_) => todo!(),
                    DaDataLightClient::Chunk(_) => todo!(),
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
        l2_genesis_state_root,
    })
}
