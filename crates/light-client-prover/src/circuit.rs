use borsh::BorshDeserialize;
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::{DaDataLightClient, DaNamespace, DaVerifier};
use sov_rollup_interface::zk::ZkvmGuest;

use crate::input::LightClientCircuitInput;
use crate::output::LightClientCircuitOutput;

#[derive(Debug)]
pub enum LightClientVerificationError {
    DaTxsCouldntBeVerified,
}

pub fn run_circuit<DaV: DaVerifier, G: ZkvmGuest>(
    da_verifier: DaV,
    guest: &G,
) -> Result<LightClientCircuitOutput, LightClientVerificationError> {
    let input: LightClientCircuitInput<DaV::Spec> = guest.read_from_host();

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

    let batch_proof_journals = input.batch_proof_journals;
    let batch_proof_method_id = input.batch_proof_method_id;
    // TODO: Test for multiple assumptions to see if the env::verify function does automatic matching between the journal and the assumption or do we need to verify them in order?
    // https://github.com/chainwayxyz/citrea/issues/1401
    for journal in batch_proof_journals {
        G::verify(&journal, &batch_proof_method_id.into()).unwrap();
    }

    // do what you want with proofs
    // complete proof has raw bytes inside
    // to extract *and* verify the proof you need to use the zk guest
    // can be passed from the guest code to this function

    Ok(LightClientCircuitOutput {
        state_root: [1; 32],
    })

    // First
}
