use borsh::BorshDeserialize;
use sov_modules_api::da::BlockHeaderTrait;
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

    // Start by verifying the previous light client proof
    // If this is the first light client proof, skip this step
    let previous_light_client_proof_output = if let Some(previous_light_client_proof_journal) =
        input.previous_light_client_proof_journal
    {
        let previous_light_client_proof_output =
            G::verify_and_extract_output::<LightClientCircuitOutput<DaV::Spec>>(
                &previous_light_client_proof_journal,
                &input.light_client_proof_method_id.into(),
            )
            .expect("Should have verified the light client proof");

        // TODO: Once we implement light client method id by spec update this to do the right checks
        // Assert that the output method id and the input method id are the same
        assert_eq!(
            input.light_client_proof_method_id,
            previous_light_client_proof_output.light_client_proof_method_id
        );
        // Verify that previous light client da block hash, matches the prev hash of the current block
        assert_eq!(
            input.da_block_header.prev_hash(),
            previous_light_client_proof_output.da_block_hash
        );

        Some(previous_light_client_proof_output)
    } else {
        None
    };

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
    // TODO: We are currently assuming batch proofs are ordered. Erce pr will handle that so I am currently ignoring that case.
    for (idx, blob) in input.da_data.iter().enumerate() {
        if blob.sender().as_ref() == input.batch_prover_da_pub_key {
            let data = DaDataLightClient::try_from_slice(blob.verified_data());

            if let Ok(data) = data {
                match data {
                    DaDataLightClient::Complete(proof) => {
                        let journal =
                            G::extract_raw_output(&proof).expect("DaData proofs must be valid");
                        let batch_proof_output: BatchProofCircuitOutput<DaV::Spec, [u8; 32]> =
                            G::verify_and_extract_output(&journal, &batch_proof_method_id.into())
                                .expect("Batch proof could not be verified");

                        if idx == 0 {
                            if let Some(ref previous_light_client_proof_output) =
                                previous_light_client_proof_output
                            {
                                // If this is the first batch proof we need to verify that
                                // previous light client proof output state root matches starting batch proof state root
                                assert_eq!(
                                    previous_light_client_proof_output.state_root,
                                    batch_proof_output.initial_state_root
                                );
                            }
                        }
                    }
                    DaDataLightClient::Aggregate(_) => todo!(),
                    DaDataLightClient::Chunk(_) => todo!(),
                }
            }
        }
    }

    // do what you want with proofs
    // complete proof has raw bytes inside
    // to extract *and* verify the proof you need to use the zk guest
    // can be passed from the guest code to this function

    Ok(LightClientCircuitOutput {
        state_root: [1; 32],
        light_client_proof_method_id: input.light_client_proof_method_id,
        da_block_hash: input.da_block_header.hash(),
    })

    // First
}
