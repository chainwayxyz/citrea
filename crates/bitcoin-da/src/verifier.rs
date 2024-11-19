use bitcoin::hashes::Hash;
use citrea_primitives::compression::decompress_blob;
use crypto_bigint::{Encoding, U256};
use itertools::Itertools;
use sov_rollup_interface::da::{
    BlockHeaderTrait, CountedBufReader, DaNamespace, DaSpec, DaVerifier, UpdatedDaState,
};
use sov_rollup_interface::zk::LightClientCircuitOutput;

use crate::helpers::parsers::{
    parse_batch_proof_transaction, parse_light_client_transaction, ParsedBatchProofTransaction,
    ParsedLightClientTransaction, VerifyParsed,
};
use crate::helpers::{calculate_double_sha256, merkle_tree};
use crate::spec::blob::{BlobBuf, BlobWithSender};
use crate::spec::BitcoinSpec;

pub const WITNESS_COMMITMENT_PREFIX: &[u8] = &[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

/// The maximum target value, which corresponds to the minimum difficulty
const MAX_TARGET: U256 =
    U256::from_be_hex("00000000FFFF0000000000000000000000000000000000000000000000000000");

/// An epoch should be two weeks (represented as number of seconds)
/// seconds/minute * minutes/hour * hours/day * 14 days
const EXPECTED_EPOCH_TIMESPAN: u32 = 60 * 60 * 24 * 14;

/// Number of blocks per epoch
const BLOCKS_PER_EPOCH: u64 = 2016;

pub struct BitcoinVerifier {
    to_batch_proof_prefix: Vec<u8>,
    to_light_client_prefix: Vec<u8>,
}

// TODO: custom errors based on our implementation
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

    // Verify that the given list of blob transactions is complete and correct.
    fn verify_transactions(
        &self,
        block_header: &<Self::Spec as DaSpec>::BlockHeader,
        blobs: &[<Self::Spec as DaSpec>::BlobTransaction],
        inclusion_proof: <Self::Spec as DaSpec>::InclusionMultiProof,
        completeness_proof: <Self::Spec as DaSpec>::CompletenessProof,
        namespace: DaNamespace,
    ) -> Result<(), Self::Error> {
        // create hash set of blobs
        let mut blobs_iter = blobs.iter();

        let prefix = match namespace {
            DaNamespace::ToBatchProver => self.to_batch_proof_prefix.as_slice(),
            DaNamespace::ToLightClientProver => self.to_light_client_prefix.as_slice(),
        };

        let relevant_wtxid_iter = inclusion_proof
            .wtxids
            .iter()
            .filter(|wtxid| wtxid.starts_with(prefix));
        for (wtxid, tx) in relevant_wtxid_iter.zip_eq(&completeness_proof) {
            // ensure completeness proof tx matches the inclusion tx
            if tx.compute_wtxid().as_byte_array() != wtxid {
                return Err(ValidationError::RelevantTxNotInProof);
            }

            // it must be parsed correctly
            match namespace {
                DaNamespace::ToBatchProver => {
                    if let Ok(parsed_tx) = parse_batch_proof_transaction(tx) {
                        match parsed_tx {
                            ParsedBatchProofTransaction::SequencerCommitment(seq_comm) => {
                                if let Some(blob_content) =
                                    verified_blob_content(&seq_comm, &mut blobs_iter)?
                                {
                                    let blob_content = blob_content.accumulator();

                                    // assert tx content is not modified
                                    if blob_content != seq_comm.body {
                                        return Err(ValidationError::BlobContentWasModified);
                                    }
                                }
                            }
                        }
                    }
                }
                DaNamespace::ToLightClientProver => {
                    if let Ok(parsed_tx) = parse_light_client_transaction(tx) {
                        match parsed_tx {
                            ParsedLightClientTransaction::Complete(complete) => {
                                if let Some(blob_content) =
                                    verified_blob_content(&complete, &mut blobs_iter)?
                                {
                                    let blob_content = blob_content.accumulator();

                                    // assert tx content is not modified
                                    let body = decompress_blob(&complete.body);
                                    if blob_content != body {
                                        return Err(ValidationError::BlobContentWasModified);
                                    }
                                }
                            }
                            ParsedLightClientTransaction::Aggregate(aggregate) => {
                                if let Some(blob_content) =
                                    verified_blob_content(&aggregate, &mut blobs_iter)?
                                {
                                    let blob_content = blob_content.accumulator();

                                    // assert tx content is not modified
                                    if blob_content != aggregate.body {
                                        return Err(ValidationError::BlobContentWasModified);
                                    }
                                }
                            }
                            ParsedLightClientTransaction::Chunk(_chunk) => {
                                // ignore
                            }
                        }
                    }
                }
            }
        }

        // assert no extra txs than the ones in the completeness proof are left
        if blobs_iter.next().is_some() {
            return Err(ValidationError::IncorrectCompletenessProof);
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
                // Relevant txs should be empty if there is no witness data because data is inscribed in the witness
                if !blobs.is_empty() {
                    return Err(ValidationError::InvalidBlock);
                }
            }
            Some(mut commitment_idx) => {
                let merkle_root =
                    merkle_tree::BitcoinMerkleTree::new(inclusion_proof.wtxids).root();

                let input_witness_value = coinbase_tx.input[0].witness.iter().next().unwrap();

                let mut vec_merkle = merkle_root.to_vec();

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
            inclusion_proof
                .coinbase_tx
                .compute_txid()
                .as_raw_hash()
                .to_byte_array(),
            0,
            inclusion_proof.coinbase_merkle_proof,
        );

        // Check that the tx root in the block header matches the tx root in the inclusion proof.
        if block_header.merkle_root() != claimed_root {
            return Err(ValidationError::IncorrectInclusionProof);
        }

        Ok(())
    }

    fn verify_header_chain(
        &self,
        previous_light_client_proof_output: &Option<LightClientCircuitOutput<Self::Spec>>,
        block_header: &<Self::Spec as DaSpec>::BlockHeader,
    ) -> Result<UpdatedDaState<Self::Spec>, Self::Error> {
        // Check 1: Verify block hash
        if !block_header.verify_hash() {
            return Err(ValidationError::InvalidBlockHash);
        }

        let target = bits_to_target(block_header.bits());
        let work_add = target_to_work(&target);

        // TODO: this is first light client proof, hardcode the first da block and verify accordingly
        let Some(previous_light_client_proof_output) = previous_light_client_proof_output else {
            return Ok(UpdatedDaState {
                hash: block_header.hash(),
                height: block_header.height(),
                // TODO: total work should be the hardcoded initial block's total_work + work_add
                total_work: work_add.to_be_bytes(),
                epoch_start_time: block_header.time().secs() as u32,
                // TODO: this is temporary fix for ci to pass until we hardcode the first da block
                prev_11_timestamps: [0; 11],
                current_target_bits: block_header.bits(),
            });
        };

        // Check 2: block heights are consecutive
        if block_header.height() - 1 != previous_light_client_proof_output.da_block_height {
            return Err(ValidationError::NonConsecutiveBlockHeight);
        }
        // Check 3: prev hash matches with prev light client proof hash
        if block_header.prev_hash() != previous_light_client_proof_output.da_block_hash {
            return Err(ValidationError::InvalidPrevBlockHash);
        }
        // Check 4: valid bits
        if block_header.bits() != previous_light_client_proof_output.da_current_target_bits {
            return Err(ValidationError::InvalidBlockBits);
        }
        // Check 5: proof of work
        if !verify_target_hash(block_header.hash().into(), target) {
            return Err(ValidationError::InvalidTargetHash);
        }
        // Check 6: valid timestamp
        if !verify_timestamp(
            block_header.time().secs() as u32,
            previous_light_client_proof_output.da_prev_11_timestamps,
        ) {
            return Err(ValidationError::InvalidTimestamp);
        }

        let epoch_block = block_header.height() % BLOCKS_PER_EPOCH;
        // Check if this is epoch block, and update time accordingly
        let mut epoch_start_time = previous_light_client_proof_output.da_epoch_start_time;
        if epoch_block == 0 {
            epoch_start_time = block_header.time().secs() as u32;
        }

        // Update previous timestamps
        let mut prev_11_timestamps = previous_light_client_proof_output.da_prev_11_timestamps;
        prev_11_timestamps[block_header.height() as usize % 11] = block_header.time().secs() as u32;

        // If the next block is epoch start block, calculate the next epoch's difficulty target
        let mut current_target_bits = block_header.bits();
        if epoch_block == BLOCKS_PER_EPOCH - 1 {
            let next_target = calculate_new_difficulty(
                epoch_start_time,
                block_header.time().secs() as u32,
                block_header.bits(),
            );
            current_target_bits = target_to_bits(&next_target);
        }

        let total_work = U256::from_be_bytes(previous_light_client_proof_output.da_total_work)
            .saturating_add(&work_add)
            .to_be_bytes();

        Ok(UpdatedDaState {
            hash: block_header.hash(),
            height: block_header.height(),
            total_work,
            epoch_start_time,
            prev_11_timestamps,
            current_target_bits,
        })
    }
}

// Get associated blob content only if signatures, hashes and public keys match
fn verified_blob_content(
    tx: &dyn VerifyParsed,
    blobs_iter: &mut dyn Iterator<Item = &BlobWithSender>,
) -> Result<Option<CountedBufReader<BlobBuf>>, ValidationError> {
    if let Some(blob_hash) = tx.get_sig_verified_hash() {
        let blob = blobs_iter.next();

        let Some(blob) = blob else {
            return Err(ValidationError::ValidBlobNotFoundInBlobs);
        };

        if blob.hash != blob_hash {
            return Err(ValidationError::BlobWasTamperedWith);
        }

        if tx.public_key() != blob.sender.0 {
            return Err(ValidationError::IncorrectSenderInBlob);
        }

        // read the supplied blob from txs
        let mut blob_content = blob.blob.clone();
        blob_content.advance(blob_content.total_len());
        Ok(Some(blob_content))
    } else {
        Ok(None)
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

#[cfg(test)]
mod tests {

    // Transactions for testing is prepared with 2 leading zeros
    // So verifier takes in [0, 0]

    use core::str::FromStr;

    use bitcoin::block::{Header, Version};
    use bitcoin::hash_types::{TxMerkleNode, WitnessMerkleNode};
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, CompactTarget, ScriptBuf, Witness};
    use sov_rollup_interface::da::{DaNamespace, DaVerifier};

    use super::BitcoinVerifier;
    use crate::helpers::merkle_tree::BitcoinMerkleTree;
    use crate::helpers::parsers::{parse_batch_proof_transaction, ParsedBatchProofTransaction};
    use crate::helpers::test_utils::{
        get_blob_with_sender, get_mock_data, get_mock_txs, get_non_segwit_mock_txs,
    };
    use crate::spec::blob::BlobWithSender;
    use crate::spec::header::HeaderWrapper;
    use crate::spec::proof::InclusionMultiProof;
    use crate::spec::transaction::TransactionWrapper;
    use crate::spec::RollupParams;
    use crate::verifier::{ValidationError, WITNESS_COMMITMENT_PREFIX};

    #[test]
    fn correct() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, completeness_proof, txs) = get_mock_data();

        assert!(verifier
            .verify_transactions(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            )
            .is_ok());
    }

    #[test]
    fn test_non_segwit_block() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });
        let header = HeaderWrapper::new(
            Header {
                version: Version::from_consensus(536870912),
                prev_blockhash: BlockHash::from_str(
                    "6b15a2e4b17b0aabbd418634ae9410b46feaabf693eea4c8621ffe71435d24b0",
                )
                .unwrap(),
                merkle_root: TxMerkleNode::from_slice(&[
                    164, 71, 72, 235, 241, 189, 131, 141, 120, 210, 207, 233, 212, 171, 56, 52, 25,
                    40, 83, 62, 135, 211, 81, 44, 3, 109, 10, 127, 210, 213, 124, 221,
                ])
                .unwrap(),
                time: 1694177029,
                bits: CompactTarget::from_unprefixed_hex("207fffff").unwrap(),
                nonce: 0,
            },
            6,
            2,
            WitnessMerkleNode::from_str(
                "a8b25755ed6e2f1df665b07e751f6acc1ff4e1ec765caa93084176e34fa5ad71",
            )
            .unwrap()
            .to_raw_hash()
            .to_byte_array(),
        );

        let block_txs = get_non_segwit_mock_txs();
        let block_txs: Vec<TransactionWrapper> = block_txs.into_iter().map(Into::into).collect();

        // block does not have any segwit txs
        let idx = block_txs[0].output.iter().position(|output| {
            output
                .script_pubkey
                .to_bytes()
                .starts_with(WITNESS_COMMITMENT_PREFIX)
        });
        assert!(idx.is_none());

        // tx with txid 00... is not relevant is in this proof
        // only used so the completeness proof is not empty
        let completeness_proof = vec![];

        let tree = BitcoinMerkleTree::new(
            block_txs
                .iter()
                .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                .collect(),
        );

        let inclusion_proof = InclusionMultiProof {
            wtxids: block_txs
                .iter()
                .map(|t| t.compute_wtxid().to_byte_array())
                .collect(),
            coinbase_tx: block_txs[0].clone(),
            coinbase_merkle_proof: tree.get_idx_path(0),
        };

        // There should not be any blobs
        let txs: Vec<BlobWithSender> = vec![];

        assert!(matches!(
            verifier.verify_transactions(
                &header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            ),
            Ok(()),
        ));
    }

    #[test]
    fn false_coinbase_input_witness_should_fail() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let header = HeaderWrapper::new(
            Header {
                version: Version::from_consensus(536870912),
                prev_blockhash: BlockHash::from_str(
                    "426524a1b644fd8c77d32621f42a74486262bbc2eaeacf43d12cdee312885f42",
                )
                .unwrap(),
                merkle_root: TxMerkleNode::from_str(
                    "34ef858c354e8fd441e49fdc9266ca2bb760034c54b28fdb660254c2546295c8",
                )
                .unwrap(),
                time: 1724662940,
                bits: CompactTarget::from_unprefixed_hex("207fffff").unwrap(),
                nonce: 0,
            },
            36,
            1001,
            WitnessMerkleNode::from_str(
                "0467b591b054383ec433945d04063742f5aabb80e52a53bc2f8ded58d350a7c5",
            )
            .unwrap()
            .to_raw_hash()
            .to_byte_array(),
        );

        let block_txs = get_mock_txs();
        let mut block_txs: Vec<TransactionWrapper> =
            block_txs.into_iter().map(Into::into).collect();

        block_txs[0].input[0].witness = Witness::from_slice(&[vec![1u8; 32]]);

        let relevant_txs_indices = [4, 6, 18, 28, 34];

        let completeness_proof = relevant_txs_indices
            .into_iter()
            .map(|i| block_txs[i].clone())
            .map(Into::into)
            .collect();

        let tree = BitcoinMerkleTree::new(
            block_txs
                .iter()
                .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                .collect(),
        );

        let mut inclusion_proof = InclusionMultiProof {
            wtxids: block_txs
                .iter()
                .map(|t| t.compute_wtxid().to_byte_array())
                .collect(),
            coinbase_tx: block_txs[0].clone(),
            coinbase_merkle_proof: tree.get_idx_path(0),
        };

        // Coinbase tx wtxid should be [0u8;32]
        inclusion_proof.wtxids[0] = [0; 32];

        let txs: Vec<BlobWithSender> = relevant_txs_indices
            .into_iter()
            .filter_map(|i| get_blob_with_sender(&block_txs[i]).ok())
            .collect();

        assert_eq!(
            verifier.verify_transactions(
                &header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            ),
            Err(ValidationError::IncorrectInclusionProof)
        );
    }

    #[test]
    fn false_coinbase_script_pubkey_should_fail() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let header = HeaderWrapper::new(
            Header {
                version: Version::from_consensus(536870912),
                prev_blockhash: BlockHash::from_str(
                    "426524a1b644fd8c77d32621f42a74486262bbc2eaeacf43d12cdee312885f42",
                )
                .unwrap(),
                merkle_root: TxMerkleNode::from_str(
                    "34ef858c354e8fd441e49fdc9266ca2bb760034c54b28fdb660254c2546295c8",
                )
                .unwrap(),
                time: 1724662940,
                bits: CompactTarget::from_unprefixed_hex("207fffff").unwrap(),
                nonce: 0,
            },
            36,
            1001,
            WitnessMerkleNode::from_str(
                "0467b591b054383ec433945d04063742f5aabb80e52a53bc2f8ded58d350a7c5",
            )
            .unwrap()
            .to_raw_hash()
            .to_byte_array(),
        );

        let block_txs = get_mock_txs();
        let mut block_txs: Vec<TransactionWrapper> =
            block_txs.into_iter().map(Into::into).collect();

        let idx = block_txs[0]
            .output
            .iter()
            .position(|output| {
                output
                    .script_pubkey
                    .to_bytes()
                    .starts_with(WITNESS_COMMITMENT_PREFIX)
            })
            .unwrap();

        // the 7th byte of script pubkey is changed from 104 to 105
        block_txs[0].output[idx].script_pubkey = ScriptBuf::from_bytes(vec![
            106, 36, 170, 33, 169, 237, 105, 181, 249, 155, 21, 242, 213, 115, 55, 123, 70, 108,
            15, 173, 14, 106, 243, 231, 186, 128, 75, 251, 178, 9, 24, 228, 200, 177, 144, 89, 95,
            182,
        ]);

        let relevant_txs_indices = [4, 6, 18, 28, 34];

        let completeness_proof = relevant_txs_indices
            .into_iter()
            .map(|i| block_txs[i].clone())
            .map(Into::into)
            .collect();

        let tree = BitcoinMerkleTree::new(
            block_txs
                .iter()
                .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                .collect(),
        );

        let mut inclusion_proof = InclusionMultiProof {
            wtxids: block_txs
                .iter()
                .map(|t| t.compute_wtxid().to_byte_array())
                .collect(),
            coinbase_tx: block_txs[0].clone(),
            coinbase_merkle_proof: tree.get_idx_path(0),
        };

        // Coinbase tx wtxid should be [0u8;32]
        inclusion_proof.wtxids[0] = [0; 32];

        let txs: Vec<BlobWithSender> = relevant_txs_indices
            .into_iter()
            .filter_map(|i| get_blob_with_sender(&block_txs[i]).ok())
            .collect();

        assert_eq!(
            verifier.verify_transactions(
                &header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            ),
            Err(ValidationError::IncorrectInclusionProof)
        );
    }

    #[test]
    fn false_witness_script_should_fail() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let header = HeaderWrapper::new(
            Header {
                version: Version::from_consensus(536870912),
                prev_blockhash: BlockHash::from_str(
                    "426524a1b644fd8c77d32621f42a74486262bbc2eaeacf43d12cdee312885f42",
                )
                .unwrap(),
                merkle_root: TxMerkleNode::from_str(
                    "34ef858c354e8fd441e49fdc9266ca2bb760034c54b28fdb660254c2546295c8",
                )
                .unwrap(),
                time: 1724662940,
                bits: CompactTarget::from_unprefixed_hex("207fffff").unwrap(),
                nonce: 0,
            },
            36,
            1001,
            WitnessMerkleNode::from_str(
                "0467b591b054383ec433945d04063742f5aabb80e52a53bc2f8ded58d350a7c5",
            )
            .unwrap()
            .to_raw_hash()
            .to_byte_array(),
        );

        let block_txs = get_mock_txs();
        let mut block_txs: Vec<TransactionWrapper> =
            block_txs.into_iter().map(Into::into).collect();

        // This is the changed witness of the 6th tx, the second byte of the second script is changed from 6b to 6c
        // This creates a different wtxid, thus the verification should fail
        let changed_witness = vec![
            hex::decode("9a80cec0e5697631f5833aa9e06c4254cc982abf48ef65fd38ea7c3791290a47911d99d88daa9781dc86fb2c8be70af6ee58b89f109c98c9a4bc6d69c2d8961d").unwrap(),
            hex::decode("206c44322e08a288964df3af45c2a11b1fc9fdbcd03cdde61d0655fbf81948fc8aad0200000063400c7efadcdf53315064d4f54752544bd3c39f1e0242ef79b6de55eb3d0d0af15b0d497bb1dc367a74dd761ed066e67d7730dff4e5c78eff0db7b2cee4932c5ce12102588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc931000e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e4d04000000000000dd040000000000006808f58003000000000077").unwrap(),
            hex::decode("c16b44322e08a288964df3af45c2a11b1fc9fdbcd03cdde61d0655fbf81948fc8a").unwrap()
        ];

        block_txs[6].input[0].witness = Witness::from_slice(&changed_witness);

        let relevant_txs_indices = [4, 6, 18, 28, 34];

        let completeness_proof = relevant_txs_indices
            .into_iter()
            .map(|i| block_txs[i].clone())
            .map(Into::into)
            .collect();

        let tree = BitcoinMerkleTree::new(
            block_txs
                .iter()
                .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                .collect(),
        );

        let mut inclusion_proof = InclusionMultiProof {
            wtxids: block_txs
                .iter()
                .map(|t| t.compute_wtxid().to_byte_array())
                .collect(),
            coinbase_tx: block_txs[0].clone(),
            coinbase_merkle_proof: tree.get_idx_path(0),
        };

        // Coinbase tx wtxid should be [0u8;32]
        inclusion_proof.wtxids[0] = [0; 32];

        let txs: Vec<BlobWithSender> = relevant_txs_indices
            .into_iter()
            .filter_map(|i| get_blob_with_sender(&block_txs[i]).ok())
            .collect();

        assert_eq!(
            verifier.verify_transactions(
                &header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            ),
            Err(ValidationError::RelevantTxNotInProof)
        );
    }

    // verifies it, and then changes the witness and sees that it cannot be verified
    #[test]
    fn different_wtxid_fails_verification() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        assert!(verifier
            .verify_transactions(
                &block_header,
                txs.as_slice(),
                inclusion_proof.clone(),
                completeness_proof.clone(),
                DaNamespace::ToBatchProver,
            )
            .is_ok());

        // cahnging the witness txid of coinbase tx to [1; 32] will make it fail
        inclusion_proof.wtxids[0] = [1; 32];

        assert!(verifier
            .verify_transactions(
                &block_header,
                txs.as_slice(),
                inclusion_proof.clone(),
                completeness_proof.clone(),
                DaNamespace::ToBatchProver,
            )
            .is_err());

        inclusion_proof.wtxids[0] = [0; 32];

        inclusion_proof.wtxids[1] = [16; 32];

        assert!(verifier
            .verify_transactions(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            )
            .is_err());
    }

    #[test]
    fn extra_tx_in_inclusion() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.wtxids.push([5; 32]);

        assert_eq!(
            verifier.verify_transactions(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            ),
            Err(ValidationError::IncorrectInclusionProof)
        );
    }

    #[test]
    #[should_panic(expected = "itertools: .zip_eq() reached end of one iterator before the other")]
    fn missing_tx_in_inclusion() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.wtxids.pop();

        // should panic
        let _ = verifier.verify_transactions(
            &block_header,
            txs.as_slice(),
            inclusion_proof,
            completeness_proof,
            DaNamespace::ToBatchProver,
        );
    }

    #[test]
    #[should_panic(expected = "itertools: .zip_eq() reached end of one iterator before the other")]
    fn empty_inclusion() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.wtxids.clear();

        // should panic
        let _ = verifier.verify_transactions(
            &block_header,
            txs.as_slice(),
            inclusion_proof,
            completeness_proof,
            DaNamespace::ToBatchProver,
        );
    }

    #[test]
    fn break_order_of_inclusion() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.wtxids.swap(0, 1);

        assert_eq!(
            verifier.verify_transactions(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            ),
            Err(ValidationError::IncorrectInclusionProof)
        );
    }

    #[test]
    #[should_panic(expected = "itertools: .zip_eq() reached end of one iterator before the other")]
    fn missing_tx_in_completeness_proof() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, mut completeness_proof, txs) = get_mock_data();

        completeness_proof.pop();

        // should panic
        let _ = verifier.verify_transactions(
            &block_header,
            txs.as_slice(),
            inclusion_proof,
            completeness_proof,
            DaNamespace::ToBatchProver,
        );
    }

    #[test]
    #[should_panic(expected = "itertools: .zip_eq() reached end of one iterator before the other")]
    fn empty_completeness_proof() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, mut completeness_proof, txs) = get_mock_data();

        completeness_proof.clear();

        // should panic
        let _ = verifier.verify_transactions(
            &block_header,
            txs.as_slice(),
            inclusion_proof,
            completeness_proof,
            DaNamespace::ToBatchProver,
        );
    }

    #[test]
    #[should_panic(expected = "itertools: .zip_eq() reached end of one iterator before the other")]
    fn non_relevant_tx_in_completeness_proof() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, mut completeness_proof, txs) = get_mock_data();

        completeness_proof.push(get_mock_txs().get(1).unwrap().clone().into());

        // should panic
        let _ = verifier.verify_transactions(
            &block_header,
            txs.as_slice(),
            inclusion_proof,
            completeness_proof,
            DaNamespace::ToBatchProver,
        );
    }

    #[test]
    fn break_completeness_proof_order() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, mut completeness_proof, txs) = get_mock_data();

        completeness_proof.swap(2, 3);

        assert_eq!(
            verifier.verify_transactions(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            ),
            Err(ValidationError::RelevantTxNotInProof)
        );
    }

    #[test]
    fn break_rel_tx_order() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, completeness_proof, mut txs) = get_mock_data();

        txs.swap(0, 1);

        assert_eq!(
            verifier.verify_transactions(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            ),
            Err(ValidationError::BlobWasTamperedWith)
        );
    }

    #[test]
    fn break_rel_tx_and_completeness_order() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, mut completeness_proof, mut txs) = get_mock_data();

        txs.swap(0, 1);
        completeness_proof.swap(0, 1);

        assert_eq!(
            verifier.verify_transactions(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            ),
            Err(ValidationError::RelevantTxNotInProof)
        );
    }

    #[test]
    fn tamper_rel_tx_content() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, completeness_proof, mut txs) = get_mock_data();

        let new_blob = vec![2; 152];

        txs[1] = BlobWithSender::new(new_blob, txs[1].sender.0.clone(), txs[1].hash);
        assert_eq!(
            verifier.verify_transactions(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            ),
            Err(ValidationError::BlobContentWasModified)
        );
    }

    #[test]
    fn tamper_senders() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, completeness_proof, mut txs) = get_mock_data();
        let tx1 = &completeness_proof[1];
        let body = {
            let parsed = parse_batch_proof_transaction(tx1).unwrap();
            let ParsedBatchProofTransaction::SequencerCommitment(seq) = parsed;
            seq.body
        };
        txs[1] = BlobWithSender::new(body, vec![2; 33], txs[1].hash);

        assert_eq!(
            verifier.verify_transactions(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            ),
            Err(ValidationError::IncorrectSenderInBlob)
        );
    }

    #[test]
    fn missing_rel_tx() {
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: vec![1, 1],
            to_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, completeness_proof, mut txs) = get_mock_data();

        txs = vec![txs[0].clone(), txs[1].clone(), txs[2].clone()];

        assert_eq!(
            verifier.verify_transactions(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
                DaNamespace::ToBatchProver,
            ),
            Err(ValidationError::ValidBlobNotFoundInBlobs)
        );
    }
}
