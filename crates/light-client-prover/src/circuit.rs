use borsh::BorshDeserialize;
use crypto_bigint::{Encoding, U256};
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::{BatchProofCircuitOutput, BlobReaderTrait, DaSpec};
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

    let previous_light_client_proof_output = verify_header_chain::<_, G>(&input);

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
        da_block_height: 0,
        da_total_work: [0; 32],
        da_current_target_bits: 0,
        da_epoch_start_time: 0,
        da_prev_11_timestamps: [0; 11],
    })

    // First
}

// Verify header chain. Returns `None` if this is the first light client proof.
fn verify_header_chain<Spec: DaSpec, G: ZkvmGuest>(
    input: &LightClientCircuitInput<Spec>,
) -> Option<LightClientCircuitOutput<Spec>> {
    let da_block_header = &input.da_block_header;

    // Immediately verify current block header hash
    assert!(da_block_header.verify_hash());

    // TODO: hardcode the first DA block and verify it
    let Some(previous_light_client_proof_journal) = &input.previous_light_client_proof_journal
    else {
        return None;
    };

    let previous_light_client_proof_output =
        G::verify_and_extract_output::<LightClientCircuitOutput<Spec>>(
            previous_light_client_proof_journal,
            &input.light_client_proof_method_id.into(),
        )
        .expect("Got invalid previous light client proof");

    // Check 1: method ids match
    assert_eq!(
        input.light_client_proof_method_id,
        previous_light_client_proof_output.light_client_proof_method_id
    );
    // Check 2: block heights are consecutive
    assert_eq!(
        da_block_header.height() - 1,
        previous_light_client_proof_output.da_block_height
    );
    // Check 3: prev hash matches with prev light client proof hash
    assert_eq!(
        da_block_header.prev_hash(),
        previous_light_client_proof_output.da_block_hash
    );
    // Check 4: valid bits
    assert_eq!(
        da_block_header.bits(),
        previous_light_client_proof_output.da_current_target_bits
    );
    // Check 5: valid timestamp
    assert!(verify_timestamp(
        da_block_header.time().secs() as u32,
        previous_light_client_proof_output.da_prev_11_timestamps
    ));

    let target = bits_to_target(previous_light_client_proof_output.da_current_target_bits);
    // Check 6: proof of work
    assert!(verify_target_hash(da_block_header.hash().into(), target));

    Some(previous_light_client_proof_output)
}

/// Verifies the block time against the median of the previous 11 blocks' timestamps
fn verify_timestamp(block_time: u32, mut prev_11_timestamps: [u32; 11]) -> bool {
    prev_11_timestamps.sort_unstable();
    let median_time = prev_11_timestamps[5];
    block_time <= median_time
}

/// Checks the validity of a block hash by comparing it to the target byte by byte.
/// Here, the hash is considered valid if it is less than the target.
/// `target_bytes` is the target in big-endian byte order.
/// `hash` is the hash in little-endian byte order.
fn verify_target_hash(hash: [u8; 32], target_bytes: [u8; 32]) -> bool {
    for i in 0..32 {
        if hash[31 - i] < target_bytes[i] {
            // The hash is valid because a byte in hash is less than the corresponding byte in target
            return true;
        } else if hash[31 - i] > target_bytes[i] {
            // The hash is invalid because a byte in hash is greater than the corresponding byte in target
            return false;
        }
        // If the bytes are equal, continue to the next byte
    }

    true
}

/// Converts the little-endian `bits` field of a block header to a big-endian target
/// value. For example, the bits `0x1d00ffff` is converted to the target
/// `0x00000000FFFF0000000000000000000000000000000000000000000000000000`.
/// Here, `"0x1d0ffff".from_be_bytes::<u32>() = 486604799` is the value you would see
/// when working with the RPC interface of a Bitcoin node. But when computing the block hash,
/// it will be serialized and used as `486604799.to_le_bytes()`.
/// Example use:
/// `bits: u32 = 486604799;
/// `,
/// See https://learnmeabitcoin.com/technical/block/#bits.
fn bits_to_target(bits: u32) -> [u8; 32] {
    let size = (bits >> 24) as usize;
    let mantissa = bits & 0x00ffffff;

    // Prepare U256 target
    let target =
    // If the size is less than or equal to 3, we need to shift the word to the right,
    // but this scenario is not likely in real life
    if size <= 3 {
        U256::from(mantissa >> (8 * (3 - size)))
    }
    // If the size is greater than 3, we need to shift the mantissa to the left
    else {
        U256::from(mantissa) << (8 * (size - 3))
    };

    target.to_be_bytes()
}

/// Calculates the work done for a block hash that satisfies a given.
/// Should use the `bits` field of the block header to calculate the target.
fn target_to_work(target: &[u8; 32]) -> U256 {
    let target = U256::from_be_slice(target);
    let target_plus_one = target.saturating_add(&U256::ONE);

    U256::MAX.wrapping_div(&target_plus_one)
}
