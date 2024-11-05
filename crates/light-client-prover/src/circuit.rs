use std::collections::HashMap;

use borsh::BorshDeserialize;
use sov_modules_api::{BlobReaderTrait, StateTransition};
use sov_rollup_interface::da::{DaDataLightClient, DaNamespace, DaVerifier};
use sov_rollup_interface::zk::{LightClientCircuitInput, LightClientCircuitOutput, ZkvmGuest};

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
    let mut deserialized_outputs: Vec<_> = input
        .batch_proof_journals
        .iter()
        .map(|journal| {
            G::verify_and_extract_output::<StateTransition<DaV::Spec, [u8; 32]>>(
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
    if let Some(previous_output) = &deserialized_previous_light_client_proof_journal {
        // Start with the previous light client proof's final state root
        let mut current_final_state_root = previous_output.state_root;

        let mut journal_map: HashMap<[u8; 32], usize> = deserialized_outputs
            .iter()
            .enumerate()
            .map(|(index, journal)| (journal.initial_state_root, index))
            .collect();

        let mut i = 0;

        while i < deserialized_outputs.len() {
            // Check if the current journal's initial state matches the expected current final state
            if deserialized_outputs[i].initial_state_root == current_final_state_root {
                // Update the current final state to this journal's final state
                current_final_state_root = deserialized_outputs[i].final_state_root;
                // Move to the next journal
                i += 1;
            } else {
                // Use the map to find the correct journal quickly
                if let Some(&pos) = journal_map.get(&current_final_state_root) {
                    if pos > i {
                        // Swap the found matching journal to the current position
                        deserialized_outputs.swap(i, pos);
                        // Update the map to reflect the swap
                        journal_map.insert(deserialized_outputs[pos].initial_state_root, pos);
                        journal_map.insert(deserialized_outputs[i].initial_state_root, i);
                    }
                } else {
                    panic!("No matching journal found for state root chaining");
                }
            }
        }
    }

    let final_state_root = deserialized_outputs.last().map_or_else(
        || {
            deserialized_previous_light_client_proof_journal
                .map_or([0u8; 32], |journal| journal.state_root)
        },
        |journal| journal.final_state_root,
    );

    Ok(LightClientCircuitOutput {
        state_root: final_state_root,
        light_client_proof_method_id: input.light_client_proof_method_id,
    })
}
