use citrea_primitives::compression::decompress_blob;
use crypto_bigint::{Encoding, U256};
use itertools::Itertools;
use sov_rollup_interface::da::{BlockHeaderTrait, DaNamespace, DaSpec, DaVerifier, LatestDaState};
use sov_rollup_interface::Network;

use crate::helpers::parsers::{
    parse_batch_proof_transaction, parse_light_client_transaction, ParsedBatchProofTransaction,
    ParsedLightClientTransaction, VerifyParsed,
};
use crate::helpers::{calculate_double_sha256, calculate_txid, calculate_wtxid, merkle_tree};
use crate::network_constants::{
    INITIAL_MAINNET_STATE, INITIAL_SIGNET_STATE, INITIAL_TESTNET4_STATE, MAINNET_CONSTANTS,
    REGTEST_CONSTANTS, SIGNET_CONSTANTS, TESTNET4_CONSTANTS,
};
use crate::spec::blob::BlobWithSender;
use crate::spec::header::HeaderWrapper;
use crate::spec::BitcoinSpec;

pub const WITNESS_COMMITMENT_PREFIX: &[u8] = &[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// An epoch should be two weeks (represented as number of seconds)
/// seconds/minute * minutes/hour * hours/day * 14 days
const EXPECTED_EPOCH_TIMESPAN: u32 = 60 * 60 * 24 * 14;

/// Number of blocks per epoch
const BLOCKS_PER_EPOCH: u64 = 2016;

#[derive(Debug)]
pub struct BitcoinVerifier {
    to_batch_proof_prefix: Vec<u8>,
    to_light_client_prefix: Vec<u8>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ValidationError {
    InvalidBlock,
    NonMatchingScript,
    InvalidSegWitCommitment,
    NonRelevantTxInProof,
    ValidBlobNotFoundInBlobs,
    BlobWasTamperedWith,
    IncorrectSenderInBlob,
    BlobContentWasModified,
    IncorrectCompletenessProof,
    RelevantTxNotInProof,
    IncorrectInclusionProof,
    FailedToCalculateMerkleRoot,
    RelevantTxNotFoundInBlock,
    InvalidBlockHash,
    NonConsecutiveBlockHeight,
    InvalidPrevBlockHash,
    InvalidBlockBits,
    InvalidTargetHash,
    InvalidTimestamp,
    HeaderInclusionTxCountMismatch,
    FailedToDeserializeCompleteChunks,
}

impl DaVerifier for BitcoinVerifier {
    type Spec = BitcoinSpec;

    type Error = ValidationError;

    fn new(params: <Self::Spec as DaSpec>::ChainParams) -> Self {
        Self {
            to_batch_proof_prefix: params.to_batch_proof_prefix,
            to_light_client_prefix: params.to_light_client_prefix,
        }
    }

    fn decompress_chunks(&self, complete_chunks: &[u8]) -> Result<Vec<u8>, Self::Error> {
        BitcoinSpec::decompress_chunks(complete_chunks)
            .map_err(|_| ValidationError::FailedToDeserializeCompleteChunks)
    }

    // Verify that the given list of blob transactions is complete and correct.
    fn verify_transactions(
        &self,
        block_header: &<Self::Spec as DaSpec>::BlockHeader,
        inclusion_proof: <Self::Spec as DaSpec>::InclusionMultiProof,
        completeness_proof: <Self::Spec as DaSpec>::CompletenessProof,
        namespace: DaNamespace,
    ) -> Result<Vec<<Self::Spec as DaSpec>::BlobTransaction>, Self::Error> {
        if block_header.tx_count as usize != inclusion_proof.wtxids.len() {
            return Err(ValidationError::HeaderInclusionTxCountMismatch);
        }

        let prefix = match namespace {
            DaNamespace::ToBatchProver => self.to_batch_proof_prefix.as_slice(),
            DaNamespace::ToLightClientProver => self.to_light_client_prefix.as_slice(),
        };

        // Optimistically assume all txs in the completeness proof are verifiable
        let mut blobs = Vec::with_capacity(completeness_proof.len());

        let relevant_wtxid_iter = inclusion_proof
            .wtxids
            .iter()
            .filter(|wtxid| wtxid.starts_with(prefix));
        for (wtxid, tx) in relevant_wtxid_iter.zip_eq(&completeness_proof) {
            // ensure completeness proof tx matches the inclusion tx
            if &calculate_wtxid(tx) != wtxid {
                return Err(ValidationError::RelevantTxNotInProof);
            }

            // it must be parsed correctly
            match namespace {
                DaNamespace::ToBatchProver => {
                    if let Ok(parsed_tx) = parse_batch_proof_transaction(tx) {
                        match parsed_tx {
                            ParsedBatchProofTransaction::SequencerCommitment(seq_comm) => {
                                if let Some(hash) = seq_comm.get_sig_verified_hash() {
                                    blobs.push(BlobWithSender::new(
                                        seq_comm.body,
                                        seq_comm.public_key,
                                        hash,
                                        Some(*wtxid),
                                    ));
                                }
                            }
                        }
                    }
                }
                DaNamespace::ToLightClientProver => {
                    if let Ok(parsed_tx) = parse_light_client_transaction(tx) {
                        match parsed_tx {
                            ParsedLightClientTransaction::Complete(complete) => {
                                if let Some(hash) = complete.get_sig_verified_hash() {
                                    blobs.push(BlobWithSender::new(
                                        decompress_blob(&complete.body),
                                        complete.public_key,
                                        hash,
                                        Some(*wtxid),
                                    ))
                                }
                            }
                            ParsedLightClientTransaction::Aggregate(aggregate) => {
                                if let Some(hash) = aggregate.get_sig_verified_hash() {
                                    blobs.push(BlobWithSender::new(
                                        aggregate.body,
                                        aggregate.public_key,
                                        hash,
                                        Some(*wtxid),
                                    ))
                                }
                            }
                            ParsedLightClientTransaction::Chunk(chunk) => {
                                blobs.push(BlobWithSender::new(
                                    chunk.body,
                                    // chunk sender and hash irrelevant
                                    vec![],
                                    [0; 32],
                                    Some(*wtxid),
                                ));
                            }
                            ParsedLightClientTransaction::BatchProverMethodId(method_id) => {
                                if let Some(hash) = method_id.get_sig_verified_hash() {
                                    blobs.push(BlobWithSender::new(
                                        method_id.body,
                                        method_id.public_key,
                                        hash,
                                        Some(*wtxid),
                                    ))
                                }
                            }
                        }
                    }
                }
            }
        }

        // verify that one of the outputs of the coinbase transaction has script pub key starting with 0x6a24aa21a9ed,
        // and the rest of the script pub key is the commitment of witness data.
        let coinbase_tx = &inclusion_proof.coinbase_tx;
        // If there are more than one scriptPubKey matching the pattern,
        // the one with highest output index is assumed to be the commitment.
        // That  is why the iterator is reversed.
        let commitment_idx = coinbase_tx.output.iter().rev().position(|output| {
            output
                .script_pubkey
                .as_bytes()
                .starts_with(WITNESS_COMMITMENT_PREFIX)
        });
        match commitment_idx {
            // If commitment does not exist
            None => {
                // TODO: add this here? PR #1822
                // if block_header.merkle_root() != block_header.txs_commitment() {
                //     return Err()
                // }

                // Relevant txs should be empty if there is no witness data because data is inscribed in the witness
                if !blobs.is_empty() {
                    return Err(ValidationError::InvalidBlock);
                }
            }
            Some(mut commitment_idx) => {
                let merkle_root =
                    merkle_tree::BitcoinMerkleTree::new(inclusion_proof.wtxids).root();

                let input_witness_value = coinbase_tx.input[0].witness.iter().next().unwrap();

                let mut vec_merkle = Vec::with_capacity(input_witness_value.len() + 32);

                vec_merkle.extend_from_slice(&merkle_root);
                vec_merkle.extend_from_slice(input_witness_value);

                // check with sha256(sha256(<merkle root><witness value>))
                let commitment = calculate_double_sha256(&vec_merkle);

                // check if the commitment is correct
                // on signet there is an additional commitment after the segwit commitment
                // so we check only the first 32 bytes after commitment header (bytes [2, 5])
                commitment_idx = coinbase_tx.output.len() - commitment_idx - 1; // The index is reversed
                let script_pubkey = coinbase_tx.output[commitment_idx].script_pubkey.as_bytes();
                if script_pubkey[6..38] != commitment {
                    return Err(ValidationError::IncorrectInclusionProof);
                }
            }
        }

        let claimed_root = merkle_tree::BitcoinMerkleTree::calculate_root_with_merkle_proof(
            calculate_txid(&inclusion_proof.coinbase_tx),
            0,
            &inclusion_proof.coinbase_merkle_proof,
        );

        // Check that the tx root in the block header matches the tx root in the inclusion proof.
        if block_header.merkle_root() != claimed_root {
            return Err(ValidationError::IncorrectInclusionProof);
        }

        Ok(blobs)
    }

    fn verify_header_chain(
        &self,
        latest_da_state: Option<&LatestDaState>,
        block_header: &<Self::Spec as DaSpec>::BlockHeader,
        network: Network,
    ) -> Result<LatestDaState, Self::Error> {
        match network {
            Network::Mainnet => self.verify_header_chain_mainnet(
                latest_da_state.unwrap_or(&INITIAL_MAINNET_STATE),
                block_header,
            ),
            Network::Testnet => self.verify_header_chain_testnet4(
                latest_da_state.unwrap_or(&INITIAL_TESTNET4_STATE),
                block_header,
            ),
            Network::Devnet => self.verify_header_chain_signet(
                latest_da_state.unwrap_or(&INITIAL_SIGNET_STATE),
                block_header,
            ),
            Network::Nightly | Network::TestNetworkWithForks => {
                // For regtest, if this is the first light client proof, we always
                // consider the block valid with respect to its parent block, so
                // it can start from anywhere.
                self.verify_header_chain_regtest(
                    latest_da_state.unwrap_or(&LatestDaState {
                        block_hash: block_header.prev_hash().to_byte_array(),
                        block_height: block_header.height() - 1,
                        // Total work is irrelevant in regtest
                        total_work: [0; 32],
                        current_target_bits: REGTEST_CONSTANTS.max_bits,
                        // Epoch start time is irrelevant in regtest
                        epoch_start_time: 0,
                        // Prev 11 timestamps is irrelevant in regtest
                        prev_11_timestamps: [0; 11],
                    }),
                    block_header,
                )
            }
        }
    }
}

impl BitcoinVerifier {
    fn verify_header_chain_mainnet(
        &self,
        latest_da_state: &LatestDaState,
        block_header: &HeaderWrapper,
    ) -> Result<LatestDaState, ValidationError> {
        let network_constants = MAINNET_CONSTANTS;

        let target = bits_to_target(latest_da_state.current_target_bits);
        let work_add = target_to_work(&target);

        // Verify common header chain rules
        self.verify_header_chain_common(
            block_header,
            latest_da_state,
            target,
            latest_da_state.current_target_bits,
        )?;

        // Update previous timestamps
        let mut prev_11_timestamps = latest_da_state.prev_11_timestamps;
        prev_11_timestamps[block_header.height() as usize % 11] = block_header.time().secs() as u32;

        let epoch_block = block_header.height() % BLOCKS_PER_EPOCH;

        // Check if this is the first epoch block, and update time accordingly
        let epoch_start_time = if epoch_block == 0 {
            block_header.time().secs() as u32
        } else {
            latest_da_state.epoch_start_time
        };

        // If this is the last block of the epoch, calculate the target for the next epoch
        let current_target_bits = if epoch_block == BLOCKS_PER_EPOCH - 1 {
            let next_target = calculate_new_difficulty(
                epoch_start_time,
                block_header.time().secs() as u32,
                block_header.bits(),
                network_constants.max_target,
            );
            target_to_bits(&next_target)
        } else {
            block_header.bits()
        };

        let total_work = U256::from_be_bytes(latest_da_state.total_work)
            .saturating_add(&work_add)
            .to_be_bytes();

        Ok(LatestDaState {
            block_hash: block_header.hash().to_byte_array(),
            block_height: block_header.height(),
            total_work,
            current_target_bits,
            epoch_start_time,
            prev_11_timestamps,
        })
    }

    fn verify_header_chain_testnet4(
        &self,
        latest_da_state: &LatestDaState,
        block_header: &HeaderWrapper,
    ) -> Result<LatestDaState, ValidationError> {
        let network_constants = TESTNET4_CONSTANTS;

        let epoch_block = block_header.height() % BLOCKS_PER_EPOCH;
        let latest_block_time =
            latest_da_state.prev_11_timestamps[latest_da_state.block_height as usize % 11];

        // If more than 20 minutes passed since latest block and this is not epoch block 0, reset target
        let (target, expected_bits) =
            if epoch_block != 0 && block_header.time().secs() as u32 > latest_block_time + 1200 {
                let target = network_constants.max_target.to_be_bytes();
                (target, network_constants.max_bits)
            } else {
                let target = bits_to_target(latest_da_state.current_target_bits);
                (target, latest_da_state.current_target_bits)
            };
        let work_add = target_to_work(&target);

        // Verify common header chain rules
        self.verify_header_chain_common(block_header, latest_da_state, target, expected_bits)?;

        // Update previous timestamps
        let mut prev_11_timestamps = latest_da_state.prev_11_timestamps;
        prev_11_timestamps[block_header.height() as usize % 11] = block_header.time().secs() as u32;

        // Check if this is the first epoch block, and update time accordingly
        let epoch_start_time = if epoch_block == 0 {
            block_header.time().secs() as u32
        } else {
            latest_da_state.epoch_start_time
        };

        // If this is the last block of the epoch, calculate the target for the next epoch
        let current_target_bits = if epoch_block == BLOCKS_PER_EPOCH - 1 {
            let next_target = calculate_new_difficulty(
                epoch_start_time,
                block_header.time().secs() as u32,
                // If 20 minute exception happened on last block of the difficulty period,
                // previous block's target should be used. If didn't happen, it is going
                // to be equal to current block bits anyway.
                latest_da_state.current_target_bits,
                network_constants.max_target,
            );
            target_to_bits(&next_target)
        } else {
            latest_da_state.current_target_bits
        };

        let total_work = U256::from_be_bytes(latest_da_state.total_work)
            .saturating_add(&work_add)
            .to_be_bytes();

        Ok(LatestDaState {
            block_hash: block_header.hash().to_byte_array(),
            block_height: block_header.height(),
            total_work,
            current_target_bits,
            epoch_start_time,
            prev_11_timestamps,
        })
    }

    fn verify_header_chain_signet(
        &self,
        latest_da_state: &LatestDaState,
        block_header: &HeaderWrapper,
    ) -> Result<LatestDaState, ValidationError> {
        let network_constants = SIGNET_CONSTANTS;

        let target = bits_to_target(latest_da_state.current_target_bits);
        let work_add = target_to_work(&target);

        // Verify common header chain rules
        self.verify_header_chain_common(
            block_header,
            latest_da_state,
            target,
            latest_da_state.current_target_bits,
        )?;

        // Update previous timestamps
        let mut prev_11_timestamps = latest_da_state.prev_11_timestamps;
        prev_11_timestamps[block_header.height() as usize % 11] = block_header.time().secs() as u32;

        let epoch_block = block_header.height() % BLOCKS_PER_EPOCH;

        // Check if this is epoch block, and update time accordingly
        let epoch_start_time = if epoch_block == 0 {
            block_header.time().secs() as u32
        } else {
            latest_da_state.epoch_start_time
        };

        // If the next block is epoch start block, calculate the next epoch's difficulty target
        let current_target_bits = if epoch_block == BLOCKS_PER_EPOCH - 1 {
            let next_target = calculate_new_difficulty(
                epoch_start_time,
                block_header.time().secs() as u32,
                block_header.bits(),
                network_constants.max_target,
            );
            target_to_bits(&next_target)
        } else {
            block_header.bits()
        };

        let total_work = U256::from_be_bytes(latest_da_state.total_work)
            .saturating_add(&work_add)
            .to_be_bytes();

        Ok(LatestDaState {
            block_hash: block_header.hash().to_byte_array(),
            block_height: block_header.height(),
            total_work,
            current_target_bits,
            epoch_start_time,
            prev_11_timestamps,
        })
    }

    fn verify_header_chain_regtest(
        &self,
        latest_da_state: &LatestDaState,
        block_header: &HeaderWrapper,
    ) -> Result<LatestDaState, ValidationError> {
        assert_ne!(block_header.height(), 0, "Height must not be 0 in regtest");

        let network_constants = REGTEST_CONSTANTS;

        // Verify common header chain rules
        self.verify_header_chain_common(
            block_header,
            latest_da_state,
            network_constants.max_target.to_be_bytes(),
            network_constants.max_bits,
        )?;

        // Update previous timestamps
        let mut prev_11_timestamps = latest_da_state.prev_11_timestamps;
        prev_11_timestamps[block_header.height() as usize % 11] = block_header.time().secs() as u32;

        Ok(LatestDaState {
            block_hash: block_header.hash().to_byte_array(),
            block_height: block_header.height(),
            total_work: [0; 32],
            current_target_bits: block_header.bits(),
            epoch_start_time: 0,
            prev_11_timestamps,
        })
    }

    fn verify_header_chain_common(
        &self,
        block_header: &HeaderWrapper,
        latest_da_state: &LatestDaState,
        target: [u8; 32],
        expected_bits: u32,
    ) -> Result<(), ValidationError> {
        // Check 1: Verify block hash
        if !block_header.verify_hash() {
            return Err(ValidationError::InvalidBlockHash);
        }
        // Check 2: block heights are consecutive
        if block_header.height() - 1 != latest_da_state.block_height {
            return Err(ValidationError::NonConsecutiveBlockHeight);
        }
        // Check 3: prev hash matches with prev light client proof hash
        if block_header.prev_hash().to_byte_array() != latest_da_state.block_hash {
            return Err(ValidationError::InvalidPrevBlockHash);
        }
        // Check 4: valid bits
        if block_header.bits() != expected_bits {
            return Err(ValidationError::InvalidBlockBits);
        }
        // Check 5: proof of work
        if !verify_target_hash(block_header.hash().into(), target) {
            return Err(ValidationError::InvalidTargetHash);
        }
        // Check 6: valid timestamp
        if !verify_timestamp(
            block_header.time().secs() as u32,
            latest_da_state.prev_11_timestamps,
        ) {
            return Err(ValidationError::InvalidTimestamp);
        }

        Ok(())
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
pub(crate) const fn target_to_bits(target: &[u8; 32]) -> u32 {
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
    current_target_bits: u32,
    max_target: U256,
) -> [u8; 32] {
    // Step 1: Calculate the actual timespan of the epoch
    let mut actual_timespan = last_timestamp - epoch_start_time;
    if actual_timespan < EXPECTED_EPOCH_TIMESPAN / 4 {
        actual_timespan = EXPECTED_EPOCH_TIMESPAN / 4;
    } else if actual_timespan > EXPECTED_EPOCH_TIMESPAN * 4 {
        actual_timespan = EXPECTED_EPOCH_TIMESPAN * 4;
    }
    // Step 2: Calculate the new target
    let new_target_bytes = bits_to_target(current_target_bits);
    let mut new_target = U256::from_be_bytes(new_target_bytes)
        .wrapping_mul(&U256::from(actual_timespan))
        .wrapping_div(&U256::from(EXPECTED_EPOCH_TIMESPAN));
    // Step 3: Clamp the new target to the maximum target
    if new_target > max_target {
        new_target = max_target;
    }

    new_target.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::ops::Deref;

    use borsh::BorshDeserialize;
    use sov_rollup_interface::da::{DaVerifier, LatestDaState};

    use super::BitcoinVerifier;
    use crate::spec::header::{BitcoinHeaderWrapper, HeaderWrapper};
    use crate::spec::RollupParams;

    fn get_verifier() -> BitcoinVerifier {
        BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![],
            to_light_client_prefix: vec![],
        })
    }

    #[test]
    fn test_header_chain_mainnet_old_blocks() {
        let verifier = get_verifier();

        let mut block_hash = [0; 32];
        hex::decode_to_slice(
            "000000006ae2e2690d771ee2ce991006d6606c97c5894e810159563a7731b39e",
            &mut block_hash,
        )
        .unwrap();
        block_hash.reverse();
        // Initial da height 40309 state
        let mut da_state = LatestDaState {
            block_hash,
            block_height: 40309,
            total_work: [0; 32],
            current_target_bits: 0x1d008cc3,
            epoch_start_time: 1265319794,
            prev_11_timestamps: [
                1266182524, 1266182598, 1266184302, 1266185866, 1266186230, 1266186530, 1266180699,
                1266181218, 1266181275, 1266182052, 1266182473,
            ],
        };

        let file = File::open("test_data/mainnet/headers-40310-42346.txt").unwrap();
        let reader = BufReader::new(file);
        for (line, height) in reader.lines().zip(40310..=42346) {
            let header_hex = line.unwrap();
            let header_bytes = hex::decode(&header_hex).unwrap();

            let inner_header =
                BitcoinHeaderWrapper::deserialize(&mut header_bytes.as_ref()).unwrap();
            let header = HeaderWrapper::new(*inner_header.deref(), 0, height, [0; 32]);

            da_state = verifier
                .verify_header_chain_mainnet(&da_state, &header)
                .expect("Header chain verification should not fail");
        }
    }

    #[test]
    fn test_header_chain_mainnet_newer_blocks() {
        let verifier = get_verifier();

        let mut block_hash = [0; 32];
        hex::decode_to_slice(
            "000000000000000000006d109e50b04ac96c15e9e47688bb264849867cc0faee",
            &mut block_hash,
        )
        .unwrap();
        block_hash.reverse();
        // Initial da height 872917 state
        let mut da_state = LatestDaState {
            block_hash,
            block_height: 872917,
            total_work: [0; 32],
            current_target_bits: 0x1702c070,
            epoch_start_time: 1731962532,
            prev_11_timestamps: [
                1733145689, 1733146032, 1733139284, 1733139502, 1733140945, 1733141528, 1733141580,
                1733142637, 1733142783, 1733143675, 1733144344,
            ],
        };

        let file = File::open("test_data/mainnet/headers-872918-874954.txt").unwrap();
        let reader = BufReader::new(file);
        for (line, height) in reader.lines().zip(872918..=874954) {
            let header_hex = line.unwrap();
            let header_bytes = hex::decode(&header_hex).unwrap();

            let inner_header =
                BitcoinHeaderWrapper::deserialize(&mut header_bytes.as_ref()).unwrap();
            let header = HeaderWrapper::new(*inner_header.deref(), 0, height, [0; 32]);

            da_state = verifier
                .verify_header_chain_mainnet(&da_state, &header)
                .expect("Header chain verification should not fail");
        }
    }

    #[test]
    fn test_header_chain_testnet4() {
        let verifier = get_verifier();

        let mut block_hash = [0; 32];
        hex::decode_to_slice(
            "000000004554e9e9ae1542b126511770012c6d6227b317efaaadea36c543519e",
            &mut block_hash,
        )
        .unwrap();
        block_hash.reverse();
        // Initial da height 40309 state
        // Even though target is as below, this block has its next blocks produced in more than 20 minutes,
        // causing their bits to be resetted.
        let mut da_state = LatestDaState {
            block_hash,
            block_height: 40309,
            total_work: [0; 32],
            current_target_bits: 0x1954fa04,
            epoch_start_time: 1722969976,
            prev_11_timestamps: [
                1724062401, 1724063602, 1724064803, 1724066004, 1724061810, 1724063011, 1724056393,
                1724057597, 1724058798, 1724059999, 1724061200,
            ],
        };

        let file = File::open("test_data/testnet4/headers-40310-42346.txt").unwrap();
        let reader = BufReader::new(file);
        for (line, height) in reader.lines().zip(40310..=42346) {
            let header_hex = line.unwrap();
            let header_bytes = hex::decode(&header_hex).unwrap();

            let inner_header =
                BitcoinHeaderWrapper::deserialize(&mut header_bytes.as_ref()).unwrap();
            let header = HeaderWrapper::new(*inner_header.deref(), 0, height, [0; 32]);

            da_state = verifier
                .verify_header_chain_testnet4(&da_state, &header)
                .expect("Header chain verification should not fail");
        }
    }
}
