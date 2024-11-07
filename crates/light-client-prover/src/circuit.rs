use borsh::BorshDeserialize;
use crypto_bigint::{Encoding, U256};
use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::{BatchProofCircuitOutput, BlobReaderTrait, DaSpec};
use sov_rollup_interface::da::{DaDataLightClient, DaNamespace, DaVerifier};
use sov_rollup_interface::zk::{LightClientCircuitInput, LightClientCircuitOutput, ZkvmGuest};

/// The maximum target value, which corresponds to the minimum difficulty
const MAX_TARGET: U256 =
    U256::from_be_hex("00000000FFFF0000000000000000000000000000000000000000000000000000");

/// An epoch should be two weeks (represented as number of seconds)
/// seconds/minute * minutes/hour * hours/day * 14 days
const EXPECTED_EPOCH_TIMESPAN: u32 = 60 * 60 * 24 * 14;

/// Number of blocks per epoch
const BLOCKS_PER_EPOCH: u64 = 2016;

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

    let block_updates =
        verify_da_block(&previous_light_client_proof_output, &input.da_block_header);

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

struct BlockUpdates<Spec: DaSpec> {
    hash: Spec::SlotHash,
    height: u64,
    total_work: [u8; 32],
    epoch_start_time: u32,
    prev_11_timestamps: [u32; 11],
    current_target_bits: u32,
}

fn verify_da_block<Spec: DaSpec>(
    previous_light_client_proof_output: &Option<LightClientCircuitOutput<Spec>>,
    da_block_header: &Spec::BlockHeader,
) -> BlockUpdates<Spec> {
    // Check 1: Verify block hash
    assert!(da_block_header.verify_hash());

    let target = bits_to_target(da_block_header.bits());
    let work_add = target_to_work(&target);

    // TODO: this is first light client proof, hardcode the first da block and verify accordingly
    let Some(previous_light_client_proof_output) = previous_light_client_proof_output else {
        return BlockUpdates {
            hash: da_block_header.hash(),
            height: da_block_header.height(),
            // TODO: total work should be the hardcoded initial block's total_work + work_add
            total_work: work_add.to_be_bytes(),
            epoch_start_time: da_block_header.time().secs() as u32,
            // TODO: this is temporary fix for ci to pass until we hardcode the first da block
            prev_11_timestamps: [0; 11],
            current_target_bits: da_block_header.bits(),
        };
    };

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
    // Check 5: proof of work
    assert!(verify_target_hash(da_block_header.hash().into(), target));
    // Check 6: valid timestamp
    assert!(verify_timestamp(
        da_block_header.time().secs() as u32,
        previous_light_client_proof_output.da_prev_11_timestamps
    ));

    let epoch_block = da_block_header.height() % BLOCKS_PER_EPOCH;
    // Check if this is epoch block, and update time accordingly
    let mut epoch_start_time = previous_light_client_proof_output.da_epoch_start_time;
    if epoch_block == 0 {
        epoch_start_time = da_block_header.time().secs() as u32;
    }

    // Update previous timestamps
    let mut prev_11_timestamps = previous_light_client_proof_output.da_prev_11_timestamps;
    prev_11_timestamps[da_block_header.height() as usize % 11] =
        da_block_header.time().secs() as u32;

    // If the next block is epoch start block, calculate the next epoch's difficulty target
    let mut current_target_bits = da_block_header.bits();
    if epoch_block == BLOCKS_PER_EPOCH - 1 {
        let next_target = calculate_new_difficulty(
            epoch_start_time,
            da_block_header.time().secs() as u32,
            da_block_header.bits(),
        );
        current_target_bits = target_to_bits(&next_target);
    }

    let total_work = U256::from_be_bytes(previous_light_client_proof_output.da_total_work)
        .saturating_add(&work_add)
        .to_be_bytes();

    BlockUpdates {
        hash: da_block_header.hash(),
        height: da_block_header.height(),
        total_work,
        epoch_start_time,
        prev_11_timestamps,
        current_target_bits,
    }
}

/// Verifies the block time against the median of the previous 11 blocks' timestamps
fn verify_timestamp(block_time: u32, mut prev_11_timestamps: [u32; 11]) -> bool {
    prev_11_timestamps.sort_unstable();
    let median_time = prev_11_timestamps[5];
    block_time > median_time
}

/// Checks the validity of a block hash by comparing it to the target byte by byte.
/// Here, the hash is considered valid if it is less than the target.
/// `target_bytes` is the target in big-endian byte order.
/// `hash` is the hash in little-endian byte order.
fn verify_target_hash(hash: [u8; 32], target_bytes: [u8; 32]) -> bool {
    for i in 0..32 {
        match hash[31 - i].cmp(&target_bytes[i]) {
            std::cmp::Ordering::Less => return true,     // Hash is valid
            std::cmp::Ordering::Greater => return false, // Hash is invalid
            std::cmp::Ordering::Equal => continue,       // Continue to the next byte if equal
        }
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

/// Converts the big-endian target value to the little-endian `bits` field of a block header.
fn target_to_bits(target: &[u8; 32]) -> u32 {
    let target_u256 = U256::from_be_slice(target);
    let target_bits = target_u256.bits();
    let size = (263 - target_bits) / 8;
    let mut compact_target = [0u8; 4];
    compact_target[0] = 33 - size as u8;
    compact_target[1] = target[size - 1_usize];
    compact_target[2] = target[size];
    compact_target[3] = target[size + 1_usize];
    u32::from_be_bytes(compact_target)
}

/// Calculates the work done for a block hash that satisfies a given.
/// Should use the `bits` field of the block header to calculate the target.
fn target_to_work(target: &[u8; 32]) -> U256 {
    let target = U256::from_be_slice(target);
    let target_plus_one = target.saturating_add(&U256::ONE);

    U256::MAX.wrapping_div(&target_plus_one)
}

/// Calculates the new difficulty target for the next epoch.
fn calculate_new_difficulty(
    epoch_start_time: u32,
    last_timestamp: u32,
    current_target: u32,
) -> [u8; 32] {
    // Step 1: Calculate the actual timespan of the epoch
    let mut actual_timespan = last_timestamp - epoch_start_time;
    if actual_timespan < EXPECTED_EPOCH_TIMESPAN / 4 {
        actual_timespan = EXPECTED_EPOCH_TIMESPAN / 4;
    } else if actual_timespan > EXPECTED_EPOCH_TIMESPAN * 4 {
        actual_timespan = EXPECTED_EPOCH_TIMESPAN * 4;
    }
    // Step 2: Calculate the new target
    let new_target_bytes = bits_to_target(current_target);
    let mut new_target = U256::from_be_bytes(new_target_bytes)
        .wrapping_mul(&U256::from(actual_timespan))
        .wrapping_div(&U256::from(EXPECTED_EPOCH_TIMESPAN));
    // Step 3: Clamp the new target to the maximum target
    if new_target > MAX_TARGET {
        new_target = MAX_TARGET;
    }

    new_target.to_be_bytes()
}
