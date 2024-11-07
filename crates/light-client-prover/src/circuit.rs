use borsh::BorshDeserialize;
use sov_modules_api::{BatchProofCircuitOutput, BlobReaderTrait};
use sov_rollup_interface::da::{DaDataLightClient, DaNamespace, DaVerifier};
use sov_rollup_interface::zk::{LightClientCircuitInput, LightClientCircuitOutput, ZkvmGuest};

#[derive(Debug)]
pub enum LightClientVerificationError {
    DaTxsCouldntBeVerified,
}

pub fn run_circuit<DaV: DaVerifier, G: ZkvmGuest>(
    da_verifier: DaV,
    guest: &G,
) -> Result<LightClientCircuitOutput<DaV::Spec>, LightClientVerificationError> {
    let input: LightClientCircuitInput<DaV::Spec> = guest.read_from_host();

    // Extract previous light client proof output
    let previous_light_client_proof_output =
        input.previous_light_client_proof_journal.map(|journal| {
            let prev_output = G::verify_and_extract_output::<LightClientCircuitOutput<DaV::Spec>>(
                &journal,
                &input.light_client_proof_method_id.into(),
            )
            .expect("Got invalid previous light client proof");
            // Method ids match
            assert_eq!(
                input.light_client_proof_method_id,
                prev_output.light_client_proof_method_id,
            );

            prev_output
        });

    let block_updates = da_verifier
        .verify_header_chain(&previous_light_client_proof_output, &input.da_block_header)
        .expect("Failed to verify DA header chain");

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

    // TODO: Test for multiple assumptions to see if the env::verify function does automatic matching between the journal and the assumption or do we need to verify them in order?
    // https://github.com/chainwayxyz/citrea/issues/1401
    let batch_proof_method_id = input.batch_proof_method_id;
    // Parse the batch proof da data
    // TODO: We are currently assuming batch proofs are ordered. Erce's pr will handle that so I am currently ignoring that case.
    for blob in input.da_data {
        if blob.sender().as_ref() == input.batch_prover_da_pub_key {
            let data = DaDataLightClient::try_from_slice(blob.verified_data());

            if let Ok(data) = data {
                match data {
                    DaDataLightClient::Complete(proof) => {
                        let journal =
                            G::extract_raw_output(&proof).expect("DaData proofs must be valid");
                        let _batch_proof_output: BatchProofCircuitOutput<DaV::Spec, [u8; 32]> =
                            G::verify_and_extract_output(&journal, &batch_proof_method_id.into())
                                .expect("Batch proof could not be verified");

                        // TODO: do necessary validations
                    }
                    DaDataLightClient::Aggregate(_) => todo!(),
                    DaDataLightClient::Chunk(_) => todo!(),
                }
            }
        }
    }

    Ok(LightClientCircuitOutput {
        state_root: [1; 32],
        light_client_proof_method_id: input.light_client_proof_method_id,
        da_block_hash: block_updates.hash,
        da_block_height: block_updates.height,
        da_total_work: block_updates.total_work,
        da_current_target_bits: block_updates.current_target_bits,
        da_epoch_start_time: block_updates.epoch_start_time,
        da_prev_11_timestamps: block_updates.prev_11_timestamps,
    })

    // First
}
