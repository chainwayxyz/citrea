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

    // Verify all batch proofs
    for journal in &input.batch_proof_journals {
        G::verify(journal, &input.batch_proof_method_id.into()).unwrap();
    }

    // Deserialize batch proof journals
    let mut deserialized_journals: Vec<_> = input
        .batch_proof_journals
        .iter()
        .map(|journal| {
            StateTransition::<DaV::Spec, [u8; 32]>::try_from_slice(journal)
                .expect("Should have deserialized the journal")
        })
        .collect();

    // Ensure the journals are sorted and check state root order
    if !deserialized_journals.is_empty() {
        // Sort the journals first
        deserialized_journals.sort_unstable_by_key(|journal| journal.sequencer_commitments_range.0);

        // Now safely access the first journal after sorting
        if let Some(first_journal) = deserialized_journals.first() {
            if let Some(previous_journal) = &deserialized_previous_light_client_proof_journal {
                assert_eq!(
                    first_journal.initial_state_root,
                    previous_journal.state_root
                );
            }
        }

        // Check if other state roots are in order
        for windows in deserialized_journals.windows(2) {
            assert_eq!(windows[0].final_state_root, windows[1].initial_state_root);
        }
    }

    // For the output state root, update with the latest state root if a batch proof journal is present
    // Otherwise, use the state root from the previous light client proof
    // If it is the first light client proof and there are no journals zero it out
    let final_state_root = deserialized_journals.last().map_or_else(
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
