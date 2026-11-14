//! This module provides the Bitcoin DA verifier implementation.

use crypto_bigint::{Encoding, U256};
use itertools::Itertools;
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec, DaVerifier, DataOnDa, LatestDaState};
use sov_rollup_interface::Network;

use crate::helpers::parsers::{parse_relevant_witness, ParsedTransaction, VerifyParsed};
use crate::helpers::{calculate_double_sha256, calculate_txid, merkle_tree};
use crate::network_constants::{
    INITIAL_MAINNET_STATE, INITIAL_SIGNET_STATE, INITIAL_TESTNET4_STATE, MAINNET_CONSTANTS,
    REGTEST_CONSTANTS, SIGNET_CONSTANTS, TESTNET4_CONSTANTS,
};
use crate::spec::blob::BlobWithSender;
use crate::spec::header::HeaderWrapper;
use crate::spec::BitcoinSpec;

/// The minimum size in bytes of the witness commitment in a block's coinbase transaction.
pub const MINIMUM_WITNESS_COMMITMENT_SIZE: usize = 38;
/// A magic constant used to signal a valid SegWit commitment.
pub const WITNESS_COMMITMENT_PREFIX: &[u8] = &[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// An epoch should be two weeks (represented as number of seconds)
const EXPECTED_EPOCH_TIMESPAN: u32 = 60 * 60 * 24 * 14;

/// While the regular expected epoch timespan is 14 days (10 minutes per block),
/// in our custom signet it is ~5.5 hours (10 seconds per block)
const EXPECTED_EPOCH_TIMESPAN_SIGNET: u32 = EXPECTED_EPOCH_TIMESPAN / 60;

/// Number of blocks per epoch
const BLOCKS_PER_EPOCH: u64 = 2016;

/// The Bitcoin verifier is responsible for verifying the integrity of Bitcoin blocks
/// and Citrea transactions within those blocks.
#[derive(Debug)]
pub struct BitcoinVerifier {
    /// The prefix of wtxids
    reveal_tx_prefix: Vec<u8>,
}

/// Validation errors that can occur during the verification of a Bitcoin block.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ValidationError {
    /// The block is invalid.
    InvalidBlock,
    /// The supplied coinbase transaction is not a valid Bitcoin coinbase transaction.
    InvalidCoinbaseTransaction,
    /// The segwit commitment in the coinbase transaction is invalid.
    InvalidSegWitCommitment,
    /// The relevant transaction is not present in the completeness proof.
    RelevantTxNotInProof,
    /// The txid commitment in the block header does not match the inclusion proof.
    IncorrectTxidCommitment,
    /// The witness commitment is incorrect.
    IncorrectWitnessCommitment,
    /// The block hash is invalid.
    InvalidBlockHash,
    /// The block heights are not consecutive.
    NonConsecutiveBlockHeight,
    /// The witness commitment structure is invalid.
    InvalidWitnessCommitmentStructure,
    /// The previous block hash does not match the expected value.
    InvalidPrevBlockHash,
    /// The block bits are invalid.
    InvalidBlockBits,
    /// The target hash is invalid.
    InvalidTargetHash,
    /// The timestamp in the block header is invalid.
    InvalidTimestamp,
    /// The inclusion proof's witness transaction list has an invalid count.
    InvalidWitnessTxidCount,
    /// The inclusion proof's coinbase witness transaction id is not zero.
    InvalidCoinbaseWitnessTxid,
    /// The witness txid Merkle tree height does not match the coinbase txid proof height.
    WitnessTxidMerkleTreeDepthMismatch,
    /// Failed to deserialize complete chunks.
    FailedToDeserializeCompleteChunks,
    /// Failed to deserialize batch proof method id body
    FailedToDeserializeBatchProofMethodIdBody,
}

impl DaVerifier for BitcoinVerifier {
    type Spec = BitcoinSpec;

    type Error = ValidationError;

    fn new(params: <Self::Spec as DaSpec>::ChainParams) -> Self {
        Self {
            reveal_tx_prefix: params.reveal_tx_prefix,
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
    ) -> Result<Vec<<Self::Spec as DaSpec>::BlobTransaction>, Self::Error> {
        let wtxids = inclusion_proof.wtxids;
        if wtxids.is_empty() {
            return Err(ValidationError::InvalidWitnessTxidCount);
        }
        if wtxids[0] != [0; 32] {
            return Err(ValidationError::InvalidCoinbaseWitnessTxid);
        }

        let coinbase_txid_merkle_proof_height = inclusion_proof.coinbase_merkle_proof.len();
        let witness_tree = merkle_tree::BitcoinMerkleTree::new(wtxids);

        // The coinbase txid proof length is authenticated by the header's txid root.
        // The witness txid list must use the same tree height, otherwise internal
        // witness Merkle nodes can be reinterpreted as fake leaves.
        if witness_tree.depth() != coinbase_txid_merkle_proof_height {
            return Err(ValidationError::WitnessTxidMerkleTreeDepthMismatch);
        }

        if !inclusion_proof.coinbase_tx.is_coinbase() {
            return Err(ValidationError::InvalidCoinbaseTransaction);
        }

        let prefix = self.reveal_tx_prefix.as_slice();

        // Optimistically assume all txs in the completeness proof are verifiable
        let mut blobs = Vec::with_capacity(completeness_proof.len());

        let relevant_wtxid_iter = witness_tree
            .leaves()
            .iter()
            .filter(|wtxid| wtxid.starts_with(prefix));
        for (wtxid, tx) in relevant_wtxid_iter.zip_eq(&completeness_proof) {
            // ensure completeness proof tx matches the inclusion tx
            if &tx.wtxid() != wtxid {
                return Err(ValidationError::RelevantTxNotInProof);
            }

            let Some(witness) = tx.reveal_witness() else {
                continue;
            };

            // it must be parsed correctly
            if let Ok(parsed_tx) = parse_relevant_witness(&witness) {
                match parsed_tx {
                    ParsedTransaction::Complete(complete) => {
                        if complete.body.first() != Some(&DataOnDa::COMPLETE_TAG) {
                            continue;
                        }
                        if !DataOnDa::validate_data_len(&complete.body) {
                            continue;
                        }
                        if let Some(hash) = complete.get_sig_verified_hash() {
                            // complete.body is compressed, but we'll leave the compression to
                            // circuit logic

                            blobs.push(BlobWithSender::new(
                                complete.body,
                                complete.public_key,
                                hash,
                                *wtxid,
                            ))
                        }
                    }
                    ParsedTransaction::Aggregate(aggregate) => {
                        if aggregate.body.first() != Some(&DataOnDa::AGGREGATE_TAG) {
                            continue;
                        }
                        if let Some(hash) = aggregate.get_sig_verified_hash() {
                            blobs.push(BlobWithSender::new(
                                aggregate.body,
                                aggregate.public_key,
                                hash,
                                *wtxid,
                            ))
                        }
                    }
                    ParsedTransaction::Chunk(chunk) => {
                        if chunk.body.first() != Some(&DataOnDa::CHUNK_TAG) {
                            continue;
                        }
                        if !DataOnDa::validate_data_len(&chunk.body) {
                            continue;
                        }
                        blobs.push(BlobWithSender::new(
                            chunk.body,
                            // chunk sender and hash irrelevant
                            vec![],
                            [0; 32],
                            *wtxid,
                        ));
                    }
                    // The verification of BatchProofMethodId security council signatures are done in the circuit
                    ParsedTransaction::BatchProofMethodId(method_id) => {
                        if method_id.body.first() != Some(&DataOnDa::BATCH_PROOF_METHOD_ID_TAG) {
                            continue;
                        }
                        // Pubkey here is given as 0 because the security council pub keys are inside the body
                        let public_key = [0u8; 32].to_vec();
                        let hash = method_id.hash();

                        blobs.push(BlobWithSender::new(
                            // Body here is: borsh(DataOnDa::BatchProofMethodId(BatchProofMethodId { ... }))
                            // The sender field here is not used because this transaction has a security council
                            // consisting of 5 public keys, this data and signatures are embedded in the body
                            method_id.body,
                            public_key,
                            hash,
                            *wtxid,
                        ))
                    }
                    ParsedTransaction::SequencerCommitment(seq_comm) => {
                        if seq_comm.body.first() != Some(&DataOnDa::SEQUENCER_COMMITMENT_TAG) {
                            continue;
                        }
                        if let Some(hash) = seq_comm.get_sig_verified_hash() {
                            blobs.push(BlobWithSender::new(
                                seq_comm.body,
                                seq_comm.public_key,
                                hash,
                                *wtxid,
                            ));
                        }
                    }
                }
            }
        }

        // If there is only coinbase tx in a block, then the witness root should be 0
        if coinbase_txid_merkle_proof_height == 0 && block_header.txs_commitment != [0; 32] {
            return Err(ValidationError::InvalidSegWitCommitment);
        }

        // verify that one of the outputs of the coinbase transaction has script pub key starting with 0x6a24aa21a9ed,
        // and the rest of the script pub key is the commitment of witness data.
        let coinbase_tx = &inclusion_proof.coinbase_tx;
        // If there are more than one scriptPubKey matching the pattern,
        // the one with highest output index is assumed to be the commitment.
        // Use rposition to match the output with the highest index matching the size and prefix requirements
        let commitment_idx = coinbase_tx.output.iter().rposition(|output| {
            output.script_pubkey.as_bytes().len() >= MINIMUM_WITNESS_COMMITMENT_SIZE
                && output
                    .script_pubkey
                    .as_bytes()
                    .starts_with(WITNESS_COMMITMENT_PREFIX)
        });

        match commitment_idx {
            // If commitment does not exist
            None => {
                // If there are more than one txs in a non segwit block, then the witness root should be the header merkle root
                if coinbase_txid_merkle_proof_height > 0
                    && block_header.merkle_root() != block_header.txs_commitment
                {
                    return Err(ValidationError::InvalidSegWitCommitment);
                }

                // Relevant txs should be empty if there is no witness data because data is inscribed in the witness
                if !blobs.is_empty() {
                    return Err(ValidationError::InvalidBlock);
                }
            }
            Some(commitment_idx) => {
                let merkle_root = witness_tree.root();

                let input_witness_value = coinbase_tx.input[0]
                    .witness
                    .iter()
                    .next()
                    .ok_or(ValidationError::InvalidWitnessCommitmentStructure)?;

                let mut vec_merkle = Vec::with_capacity(input_witness_value.len() + 32);

                vec_merkle.extend_from_slice(&merkle_root);
                vec_merkle.extend_from_slice(input_witness_value);

                // check with sha256(sha256(<merkle root><witness value>))
                let commitment = calculate_double_sha256(&vec_merkle);

                // check if the commitment is correct
                // on signet there is an additional commitment after the segwit commitment
                // so we check only the first 32 bytes after commitment header (bytes [2, 5])
                let script_pubkey = coinbase_tx.output[commitment_idx].script_pubkey.as_bytes();
                if script_pubkey[6..38] != commitment {
                    return Err(ValidationError::IncorrectWitnessCommitment);
                }

                if merkle_root != block_header.txs_commitment {
                    return Err(ValidationError::InvalidSegWitCommitment);
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
            return Err(ValidationError::IncorrectTxidCommitment);
        }

        Ok(blobs)
    }

    /// This function verifies the header chain of Bitcoin blocks
    /// applying the rules of the specified network.
    /// The rules may differ between networks such as Mainnet, Testnet, Devnet, etc.
    /// It checks for common header chain rules first, then for the specific rules of the network.
    ///
    /// Returns the latest data availability state in case of success,
    /// or an error if the verification fails.
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
            Network::Nightly => {
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
    /// Verifies the header chain for the mainnet.
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
                EXPECTED_EPOCH_TIMESPAN,
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

    /// Verifies the header chain for the testnet4 network.
    fn verify_header_chain_testnet4(
        &self,
        latest_da_state: &LatestDaState,
        block_header: &HeaderWrapper,
    ) -> Result<LatestDaState, ValidationError> {
        let network_constants = TESTNET4_CONSTANTS;

        let epoch_block = block_header.height() % BLOCKS_PER_EPOCH;
        let latest_block_time =
            latest_da_state.prev_11_timestamps[latest_da_state.block_height as usize % 11];

        // BIP94: the first block of a Testnet4 epoch may go back at most
        // ten minutes relative to its predecessor, even when MTP allows more.
        if epoch_block == 0 && block_header.time().secs() < i64::from(latest_block_time) - 600 {
            return Err(ValidationError::InvalidTimestamp);
        }

        // If more than 20 minutes passed since latest block and this is not epoch block 0, reset target
        let (target, expected_bits) = if epoch_block != 0
            && block_header.time().secs() > i64::from(latest_block_time) + 1200
        {
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
                EXPECTED_EPOCH_TIMESPAN,
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

    /// Verifies the header chain for the signet network.
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
                EXPECTED_EPOCH_TIMESPAN_SIGNET,
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

    /// Verifies the header chain for the regtest network.
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

    /// Verifies the common rules for Bitcoin block headers.
    /// This includes:
    /// 1. Verifying the block hash
    /// 2. Ensuring block heights are consecutive
    /// 3. Checking the previous block hash matches the latest DA state
    /// 4. Validating the block bits
    /// 5. Verifying the proof of work against the target hash
    /// 6. Validating the timestamp against the median of the previous 11 timestamps
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
        if target == [0; 32] || !verify_target_hash(block_header.hash().into(), target) {
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

    // Mantissa is signed in Bitcoin core, if the sign bit is set, the target is set to 0.
    // https://github.com/bitcoin/bitcoin/blob/ee42d59d4de970769ebabf77b89ff4269498f61e/src/arith_uint256.cpp#L175
    if mantissa > 0x7F_FFFF
        || size > 34
        || (mantissa > 0xff && size > 33)
        || (mantissa > 0xffff && size > 32)
    {
        return [0; 32];
    }

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
    compact_target[0] = if target_bits == 0 { 0 } else { 33 - size as u8 };
    compact_target[1] = if size == 0 { 0 } else { target[size - 1] };
    compact_target[2] = if size < 32 { target[size] } else { 0 };
    compact_target[3] = if size < 31 { target[size + 1] } else { 0 };
    u32::from_be_bytes(compact_target)
}

/// Calculates the work done for a block hash that satisfies a given.
/// Should use the `bits` field of the block header to calculate the target.
///
/// This calculation uses the mathematical identity:
/// 2**256 / (x + 1) == ~x / (x + 1) + 1
fn target_to_work(target: &[u8; 32]) -> U256 {
    // Bitcoin Core's GetBlockProof assigns no work to an invalid zero target.
    let target = U256::from_be_slice(target);
    if target == U256::ZERO {
        return U256::ZERO;
    }
    // We define the inverse of max as 1.
    if target == U256::MAX {
        return U256::ONE;
    }

    let comp = !target;

    let ret = comp.wrapping_div(&target.wrapping_add(&U256::ONE));
    ret.wrapping_add(&U256::ONE)
}

/// Calculates the new difficulty target for the next epoch.
fn calculate_new_difficulty(
    epoch_start_time: u32,
    last_timestamp: u32,
    current_target_bits: u32,
    max_target: U256,
    expected_epoch_timespan: u32,
) -> [u8; 32] {
    // Step 1: Calculate the actual timespan of the epoch
    let mut actual_timespan = last_timestamp.saturating_sub(epoch_start_time);
    if actual_timespan < expected_epoch_timespan / 4 {
        actual_timespan = expected_epoch_timespan / 4;
    } else if actual_timespan > expected_epoch_timespan * 4 {
        actual_timespan = expected_epoch_timespan * 4;
    }
    // Step 2: Calculate the new target
    let new_target_bytes = bits_to_target(current_target_bits);
    let mut new_target = U256::from_be_bytes(new_target_bytes)
        .wrapping_mul(&U256::from(actual_timespan))
        .wrapping_div(&U256::from(expected_epoch_timespan));
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

    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as HeaderVersion};
    use bitcoin::hashes::Hash;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Txid, Witness,
    };
    use borsh::BorshDeserialize;
    use crypto_bigint::{Encoding, U256};
    use hex;
    use sov_rollup_interface::da::{DaVerifier, LatestDaState};
    use sov_rollup_interface::Network;

    use super::{BitcoinVerifier, ValidationError};
    use crate::spec::header::{BitcoinHeaderWrapper, HeaderWrapper};
    use crate::spec::proof::InclusionMultiProof;
    use crate::spec::transaction::TransactionWrapper;
    use crate::spec::RollupParams;
    use crate::verifier::{bits_to_target, target_to_work};

    fn get_verifier() -> BitcoinVerifier {
        BitcoinVerifier::new(RollupParams {
            reveal_tx_prefix: vec![],
            network: Network::Nightly,
        })
    }

    #[test]
    fn test_compact_target_boundaries() {
        // Core SetCompact/GetCompact: small values, sign bit, overflow limits.
        for (bits, value) in [
            (0, 0u64),
            (0x01010000, 1),
            (0x02008000, 128),
            (0x03008000, 32768),
            (0x03010000, 65536),
        ] {
            let target = U256::from(value).to_be_bytes();
            assert_eq!(bits_to_target(bits), target);
            assert_eq!(super::target_to_bits(&target), bits);
        }
        for bits in [0x1d80ffff, 0x23000001, 0x22000100, 0x21010000, 0xff123456] {
            assert_eq!(bits_to_target(bits), [0; 32]);
        }
        assert_eq!(
            bits_to_target(0x220000ff),
            (U256::from(255u64) << 248).to_be_bytes()
        );
        assert_eq!(
            bits_to_target(0x2100ffff),
            (U256::from(65535u64) << 240).to_be_bytes()
        );
    }

    #[test]
    fn test_retarget_signed_time_and_clamps() {
        let bits = 0x1c123456;
        let expected = U256::from_be_bytes(bits_to_target(bits))
            .wrapping_div(&U256::from(4u64))
            .to_be_bytes();
        for (first, last) in [(2_000_000, 1_000_000), (u32::MAX, 0), (1, 1)] {
            assert_eq!(
                super::calculate_new_difficulty(
                    first,
                    last,
                    bits,
                    super::MAINNET_CONSTANTS.max_target,
                    super::EXPECTED_EPOCH_TIMESPAN
                ),
                expected
            );
        }
    }

    #[test]
    fn test_testnet4_epoch_timewarp_boundary() {
        let mut state = LatestDaState {
            block_hash: [0; 32],
            block_height: 2015,
            total_work: [0; 32],
            current_target_bits: 0x1d00ffff,
            epoch_start_time: 0,
            prev_11_timestamps: [1; 11],
        };
        state.prev_11_timestamps[2015 % 11] = 10_000;
        for (time, rejected) in [(9399, true), (9400, false), (9401, false)] {
            let header = HeaderWrapper::new(
                Header {
                    version: HeaderVersion::ONE,
                    prev_blockhash: BlockHash::all_zeros(),
                    merkle_root: TxMerkleNode::all_zeros(),
                    time,
                    bits: CompactTarget::from_consensus(0x1d00ffff),
                    nonce: 0,
                },
                1,
                2016,
                [0; 32],
            );
            let result = get_verifier().verify_header_chain_testnet4(&state, &header);
            // Unmined headers fail PoW, but only the too-early one fails the epoch guard.
            assert_eq!(result == Err(ValidationError::InvalidTimestamp), rejected);
        }
    }

    #[test]
    fn test_testnet4_min_difficulty_timestamp_overflow() {
        let state = LatestDaState {
            block_hash: [0; 32],
            block_height: 2016,
            total_work: [0; 32],
            current_target_bits: 0x1c123456,
            epoch_start_time: 0,
            prev_11_timestamps: [u32::MAX - 600; 11],
        };
        let header = HeaderWrapper::new(
            Header {
                version: HeaderVersion::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: u32::MAX,
                bits: CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            1,
            2017,
            [0; 32],
        );
        assert_eq!(
            get_verifier().verify_header_chain_testnet4(&state, &header),
            Err(ValidationError::InvalidBlockBits)
        );
    }

    #[test]
    fn test_verify_transactions_rejects_nonzero_coinbase_wtxid() {
        let verifier = get_verifier();
        let header = HeaderWrapper::new(
            Header {
                version: bitcoin::block::Version::from_consensus(0),
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            1,
            1,
            [0; 32],
        );
        let coinbase_tx = TransactionWrapper::from(Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let inclusion_proof = InclusionMultiProof {
            wtxids: vec![[1; 32]],
            coinbase_tx,
            coinbase_merkle_proof: vec![],
        };

        assert_eq!(
            verifier.verify_transactions(&header, inclusion_proof, vec![]),
            Err(ValidationError::InvalidCoinbaseWitnessTxid)
        );
    }

    #[test]
    fn test_verify_transactions_rejects_non_coinbase_tx() {
        let verifier = get_verifier();

        let fake_coinbase = Transaction {
            version: TxVersion(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![],
        };
        assert!(!fake_coinbase.is_coinbase());

        let header = Header {
            version: HeaderVersion::from_consensus(0x20000000),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time: 0,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        let header = HeaderWrapper::new(header, 1, 1, [0; 32]);
        let inclusion_proof = InclusionMultiProof {
            wtxids: vec![[0; 32]],
            coinbase_tx: fake_coinbase.into(),
            coinbase_merkle_proof: vec![],
        };

        assert_eq!(
            verifier.verify_transactions(&header, inclusion_proof, vec![]),
            Err(ValidationError::InvalidCoinbaseTransaction)
        );
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
        // causing their bits to be reset.
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

    #[test]
    fn test_verify_header_chain_common_sad_paths() {
        let verifier = get_verifier();

        // mainnet block 872918
        let header_hex = "00000020eefac07c86494826bb8876e4e9156cc94ab0509e106d0000000000000000000049aa89bafff85ba60886976cf8203b75baf951d52ed2a5af6e8769e0df1528a436b94d6770c0021730278e2d";
        let header_bytes = hex::decode(header_hex).unwrap();
        let inner_header = BitcoinHeaderWrapper::deserialize(&mut header_bytes.as_ref()).unwrap();

        // initial da height 872917 state
        let da_state = LatestDaState {
            block_hash: inner_header.prev_blockhash.as_raw_hash().to_byte_array(),
            block_height: 872917,
            total_work: [0; 32],
            current_target_bits: 0x1702c070,
            epoch_start_time: 1731962532,
            prev_11_timestamps: [
                1733145689, 1733146032, 1733139284, 1733139502, 1733140945, 1733141528, 1733141580,
                1733142637, 1733142783, 1733143675, 1733144344,
            ],
        };

        let target = bits_to_target(0x1702c070);
        let expected_bits = 0x1702c070;

        // invalid block hash
        let mut header = HeaderWrapper::new(*inner_header, 0, 872918, [0; 32]);
        header.precomputed_hash = [1; 32].into();
        let result = verifier.verify_header_chain_common(&header, &da_state, target, expected_bits);
        assert_eq!(result, Err(ValidationError::InvalidBlockHash));

        // non-consecutive block height
        let header = HeaderWrapper::new(*inner_header, 0, 872920, [0; 32]);
        let result = verifier.verify_header_chain_common(&header, &da_state, target, expected_bits);
        assert_eq!(result, Err(ValidationError::NonConsecutiveBlockHeight));

        // invalid prev block hash
        let mut bad_state = da_state.clone();
        bad_state.block_hash = [1; 32];
        let header = HeaderWrapper::new(*inner_header, 0, 872918, [0; 32]);
        let result =
            verifier.verify_header_chain_common(&header, &bad_state, target, expected_bits);
        assert_eq!(result, Err(ValidationError::InvalidPrevBlockHash));

        // invalid bits
        let wrong_bits = 0x1702c071;
        let header = HeaderWrapper::new(*inner_header, 0, 872918, [0; 32]);
        let result = verifier.verify_header_chain_common(&header, &da_state, target, wrong_bits);
        assert_eq!(result, Err(ValidationError::InvalidBlockBits));

        // invalid target hash
        let mut bad_header = *inner_header;
        // make target more strict by lowering the mantissa
        bad_header.bits = CompactTarget::from_consensus(0x1702c060);
        let header = HeaderWrapper::new(
            bad_header,
            0,
            872918,
            bad_header.block_hash().to_byte_array(),
        );
        let strict_target = bits_to_target(0x1702c060);
        let result =
            verifier.verify_header_chain_common(&header, &da_state, strict_target, 0x1702c060);
        assert_eq!(result, Err(ValidationError::InvalidTargetHash));

        // invalid timestamp
        let mut bad_state = da_state.clone();
        // increase all timestamps to make the median higher than the block's time
        bad_state.prev_11_timestamps = [
            1833146000, 1833146100, 1833146200, 1833146300, 1833146400, 1833146500, 1833146600,
            1833146700, 1833146800, 1833146900, 1833147000,
        ];
        let header = HeaderWrapper::new(*inner_header, 0, 872918, [0; 32]);
        let result =
            verifier.verify_header_chain_common(&header, &bad_state, target, expected_bits);
        assert_eq!(result, Err(ValidationError::InvalidTimestamp));
    }

    #[test]
    fn test_calculate_work() {
        let mut target: [u8; 32] = [0u8; 32];
        let work = target_to_work(&target);
        assert_eq!(work, U256::ZERO);
        target[31] = 1;
        let work = target_to_work(&target);
        assert_eq!(work, U256::ONE << 255);
        let target: [u8; 32] = [0xFF; 32];
        let work = target_to_work(&target);
        assert_eq!(work, U256::ONE);

        let target: [u8; 32] =
            hex::decode("00000000FFFF0000000000000000000000000000000000000000000000000000")
                .unwrap()
                .try_into()
                .unwrap();
        let work = target_to_work(&target);
        assert_eq!(
            work,
            U256::from_be_hex("0000000000000000000000000000000000000000000000000000000100010001")
        );
    }

    #[test]
    fn test_mainnet_chainworks() {
        let file = File::open("test_data/mainnet/chainwork_test_hashes.json").unwrap();
        let chain_work_test_hashes_json: serde_json::Value = serde_json::from_reader(file).unwrap();
        let chain_work_test_hashes: Vec<(&str, &str, &str)> = chain_work_test_hashes_json
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                let arr = entry.as_array().unwrap();
                (
                    arr[0].as_str().unwrap(),
                    arr[1].as_str().unwrap(),
                    arr[2].as_str().unwrap(),
                )
            })
            .collect();

        for (bits, expected_chainwork, prev_chainwork) in chain_work_test_hashes {
            let bits: u32 = u32::from_str_radix(bits, 16).unwrap();
            let expected_chainwork = U256::from_be_hex(expected_chainwork);
            let prev_chainwork = U256::from_be_hex(prev_chainwork);
            let target = bits_to_target(bits);
            let calculated_chainwork = target_to_work(&target);
            assert_eq!(
                calculated_chainwork.wrapping_add(&prev_chainwork),
                expected_chainwork
            );
        }
    }
}
