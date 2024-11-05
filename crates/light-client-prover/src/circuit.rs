use borsh::BorshDeserialize;
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::{DaDataLightClient, DaNamespace, DaVerifier};
use sov_rollup_interface::zk::{
    BatchProofCircuitOutput, BatchProofInfo, LightClientCircuitInput, LightClientCircuitOutput,
    ZkvmGuest,
};

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

    // If we have a previous light client proof, check they can be chained
    // If not, skip for now
    // TODO: Once we have a manually planted light client proof use that and assume prev light client proof always exists
    // So there will be no need for all these checks

    // Mapping from initial state root to final state root and last L2 height
    let mut initial_to_final = std::collections::BTreeMap::<[u8; 32], ([u8; 32], u64)>::new();

    let mut unverified_outputs = vec![];

    let mut last_state_root = [0u8; 32];
    let mut last_l2_height = 0;

    if let Some(previous_output) = &deserialized_previous_light_client_proof_journal {
        for unverified_info in previous_output.unverified_batch_proofs_info.iter() {
            if unverified_info.last_l2_height <= previous_output.last_l2_height {
                continue;
            }
            if let Some((final_root, last_l2)) =
                initial_to_final.remove(&unverified_info.final_state_root)
            {
                initial_to_final
                    .entry(unverified_info.initial_state_root)
                    .or_insert((final_root, last_l2));
            }
        }

        for output in deserialized_outputs.iter() {
            if output.last_l2_height <= previous_output.last_l2_height {
                continue;
            }

            if let Some((final_root, last_l2)) = initial_to_final.remove(&output.final_state_root) {
                initial_to_final
                    .entry(output.initial_state_root)
                    .or_insert((final_root, last_l2));
            }
        }

        // Collect the entries into a vector to avoid multiple borrows during iteration
        let entries: Vec<(_, (_, _))> = initial_to_final
            .iter()
            .map(|(k, v)| (*k, (v.0, v.1)))
            .collect();

        for (initial_root, (final_root, last_l2)) in entries {
            // Directly remove the entry to ensure there is no simultaneous mutable and immutable borrow
            if let Some((final_root_value, last_l2_value)) = initial_to_final.remove(&final_root) {
                // Insert the new entry after removing to avoid mutable borrow issues
                initial_to_final.insert(initial_root, (final_root_value, last_l2_value));
            } else {
                // If there is no entry for the final root, create a new `BatchProofInfo` and push it
                let unverified_info = BatchProofInfo {
                    initial_state_root: initial_root,
                    final_state_root: final_root,
                    last_l2_height: last_l2,
                };
                unverified_outputs.push(unverified_info);
            }
        }

        // Check if the final state root of the prev light client proof matches the initial state root of the first batch proof
        if let Some((final_root, last_l2)) = initial_to_final.get(&previous_output.state_root) {
            // Update the last L2 height and state root
            last_state_root = *final_root;
            last_l2_height = *last_l2;
        } else {
            // Batch proof(s) missing, chain is broken
            // Push the latest roots to unverified outputs
            last_state_root = previous_output.state_root;
            last_l2_height = previous_output.last_l2_height;

            // Throw the remaining roots into unverified outputs
            for (initial_root, (final_root, last_l2)) in initial_to_final.iter() {
                let unverified_info = BatchProofInfo {
                    initial_state_root: *initial_root,
                    final_state_root: *final_root,
                    last_l2_height: *last_l2,
                };
                unverified_outputs.push(unverified_info);
            }
        }
    }

    Ok(LightClientCircuitOutput {
        state_root: last_state_root,
        light_client_proof_method_id: input.light_client_proof_method_id,
        unverified_batch_proofs_info: unverified_outputs,
        last_l2_height,
    })
}
