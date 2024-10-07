use borsh::BorshDeserialize;
use sov_modules_api::BlobReaderTrait;
use sov_rollup_interface::da::{DaDataLightClient, DaSpec, DaVerifier};

use crate::input::LightClientCircuitInput;
use crate::output::LightClientCircuitOutput;

#[derive(Debug)]
pub enum LightClientVerificationError {
    DaTxsCouldntBeVerified,
}

pub fn run_circuit<DaV: DaVerifier>(
    input: LightClientCircuitInput<DaV::Spec>,
    da_verifier: DaV,
) -> Result<LightClientCircuitOutput, LightClientVerificationError> {
    // Veriy data from da
    let _validity_condition = da_verifier
        .verify_relevant_tx_list_light_client(
            &input.da_block_header,
            input.da_data.as_slice(),
            input.inclusion_proof,
            input.completeness_proof,
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

    // do what you want with proofs
    // complete proof has raw bytes inside
    // to extract *and* verift the proof you need to use the zkguest
    // can be passed from the guest code to this function

    Ok(LightClientCircuitOutput {
        state_root: [1; 32],
    })

    // First
}
