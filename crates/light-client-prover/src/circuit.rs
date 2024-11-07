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
}

pub fn run_circuit<DaV: DaVerifier, G: ZkvmGuest>(
    da_verifier: DaV,
    guest: &G,
) -> Result<LightClientCircuitOutput, LightClientVerificationError> {
    let input: LightClientCircuitInput<DaV::Spec> = guest.read_from_host();

    // Verify the previous light client proof if it exists
    let deserialized_previous_light_client_proof_journal = input
        .light_client_proof_journal
        .as_ref()
        .map(|proof_journal| {
            let deserialized = G::verify_and_extract_output::<LightClientCircuitOutput>(
                proof_journal,
                &input.light_client_proof_method_id.into(),
            )
            .expect("Should have verified the light client proof");

            // Ensure input and output method IDs match
            // TODO: Once we have light client method id by spec update accordingly
            assert_eq!(
                input.light_client_proof_method_id,
                deserialized.light_client_proof_method_id
            );
            deserialized
        });

    // Verify data from da
    let _validity_condition = da_verifier
        .verify_transactions(
            &input.da_block_header,
            input.da_data.as_slice(),
            input.inclusion_proof,
            input.completeness_proof,
            DaNamespace::ToLightClientProver,
        )
        .map_err(|_| LightClientVerificationError::DaTxsCouldntBeVerified)?;

    let mut complete_proofs = vec![];
    // Try parsing the data
    for blob in input.da_data {
        if blob.sender().as_ref() == input.batch_prover_da_pub_key {
            let data = DaDataLightClient::try_from_slice(blob.verified_data());

            if let Ok(data) = data {
                match data {
                    DaDataLightClient::Complete(proof) => {
                        complete_proofs.push(proof);
                    }
                    DaDataLightClient::Aggregate(_) => todo!(),
                    DaDataLightClient::Chunk(_) => todo!(),
                }
            }
        }
    }

    // Deserialize batch proof journals
    let deserialized_outputs: Vec<_> = input
        .batch_proof_journals
        .iter()
        .map(|journal| {
            G::verify_and_extract_output::<BatchProofCircuitOutput<DaV::Spec, [u8; 32]>>(
                journal,
                &input.batch_proof_method_id.into(),
            )
            .expect("Should have verified and extracted the batch proof")
        })
        .collect();

    // Mapping from initial state root to final state root and last L2 height
    let mut initial_to_final = std::collections::BTreeMap::<[u8; 32], ([u8; 32], u64)>::new();

    let (mut last_state_root, mut last_l2_height, l2_genesis_state_root) =
        deserialized_previous_light_client_proof_journal
            .as_ref()
            .map_or_else(
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
    if let Some(previous_output) = &deserialized_previous_light_client_proof_journal {
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

    for output in deserialized_outputs.iter() {
        // Do not add if last l2 height is smaller or equal to previous output
        // This is to defend against replay attacks, for example if somehow there is the script of batch proof 1 we do not need to go through it again
        if output.last_l2_height <= last_l2_height {
            continue;
        }
        recursive_match_state_roots(
            &mut initial_to_final,
            &BatchProofInfo::new(
                output.initial_state_root,
                output.final_state_root,
                output.last_l2_height,
            ),
        );
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
        unchained_batch_proofs_info: unchained_outputs,
        last_l2_height,
        l2_genesis_state_root,
    })
}
