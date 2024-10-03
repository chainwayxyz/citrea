use std::collections::BTreeSet;

use bitcoin::hashes::Hash;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec, DaVerifier};
use sov_rollup_interface::digest::Digest;
use sov_rollup_interface::zk::ValidityCondition;
use thiserror::Error;

use crate::helpers::compression::decompress_blob;
use crate::helpers::parsers::{
    parse_batch_proof_transaction, parse_light_client_transaction, ParsedBatchProofTransaction,
    ParsedLightClientTransaction, VerifyParsed,
};
use crate::helpers::{calculate_double_sha256, merkle_tree};
use crate::spec::BitcoinSpec;

pub const WITNESS_COMMITMENT_PREFIX: &[u8] = &[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];

pub struct BitcoinVerifier {
    reveal_batch_prover_prefix: Vec<u8>,
    reveal_light_client_prefix: Vec<u8>,
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
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Hash,
    BorshDeserialize,
    BorshSerialize,
)]
/// A validity condition expressing that a chain of DA layer blocks is contiguous and canonical
pub struct ChainValidityCondition {
    pub prev_hash: [u8; 32],
    pub block_hash: [u8; 32],
}
#[derive(Error, Debug)]
pub enum ValidityConditionError {
    #[error("conditions for validity can only be combined if the blocks are consecutive")]
    BlocksNotConsecutive,
}

impl ValidityCondition for ChainValidityCondition {
    type Error = ValidityConditionError;
    fn combine<H: Digest>(&self, rhs: Self) -> Result<Self, Self::Error> {
        if self.block_hash != rhs.prev_hash {
            return Err(ValidityConditionError::BlocksNotConsecutive);
        }
        Ok(rhs)
    }
}

impl DaVerifier for BitcoinVerifier {
    type Spec = BitcoinSpec;

    type Error = ValidationError;

    fn new(params: <Self::Spec as DaSpec>::ChainParams) -> Self {
        Self {
            reveal_batch_prover_prefix: params.reveal_batch_prover_prefix,
            reveal_light_client_prefix: params.reveal_light_client_prefix,
        }
    }

    // Verify that the given list of blob transactions is complete and correct.
    fn verify_relevant_tx_list(
        &self,
        block_header: &<Self::Spec as DaSpec>::BlockHeader,
        blobs: &[<Self::Spec as DaSpec>::BlobTransaction],
        inclusion_proof: <Self::Spec as DaSpec>::InclusionMultiProof,
        completeness_proof: <Self::Spec as DaSpec>::CompletenessProof,
    ) -> Result<<Self::Spec as DaSpec>::ValidityCondition, Self::Error> {
        // create hash set of blobs
        let mut blobs_iter = blobs.iter();

        let mut inclusion_iter = inclusion_proof.wtxids.iter();

        let prefix = self.reveal_batch_prover_prefix.as_slice();
        // Check starting bytes tx that parsed correctly is in blobs
        let mut completeness_tx_hashes = BTreeSet::new();

        for tx in completeness_proof.iter() {
            let wtxid = tx.compute_wtxid();
            // make sure it starts with the correct prefix
            if !wtxid.as_byte_array().starts_with(prefix) {
                return Err(ValidationError::NonRelevantTxInProof);
            }

            // make sure completeness txs are ordered same in inclusion proof
            // this logic always start seaching from the last found index
            // ordering should be preserved naturally
            let is_found_in_block =
                inclusion_iter.any(|wtxid_inc| wtxid_inc == wtxid.as_byte_array());
            if !is_found_in_block {
                return Err(ValidationError::RelevantTxNotFoundInBlock);
            }

            // it must be parsed correctly
            if let Ok(parsed_tx) = parse_batch_proof_transaction(tx) {
                match parsed_tx {
                    ParsedBatchProofTransaction::SequencerCommitment(seq_comm) => {
                        if let Some(blob_hash) = seq_comm.get_sig_verified_hash() {
                            let blob = blobs_iter.next();

                            if blob.is_none() {
                                return Err(ValidationError::ValidBlobNotFoundInBlobs);
                            }

                            let blob = blob.unwrap();
                            if blob.hash != blob_hash {
                                return Err(ValidationError::BlobWasTamperedWith);
                            }

                            if seq_comm.public_key != blob.sender.0 {
                                return Err(ValidationError::IncorrectSenderInBlob);
                            }

                            // read the supplied blob from txs
                            let mut blob_content = blob.blob.clone();
                            blob_content.advance(blob_content.total_len());
                            let blob_content = blob_content.accumulator();

                            // assert tx content is not modified
                            if blob_content != seq_comm.body {
                                return Err(ValidationError::BlobContentWasModified);
                            }
                        }
                    }
                }
            }

            completeness_tx_hashes.insert(wtxid.to_byte_array());
        }

        // assert no extra txs than the ones in the completeness proof are left
        if blobs_iter.next().is_some() {
            return Err(ValidationError::IncorrectCompletenessProof);
        }

        // no prefix bytes left behind completeness proof
        inclusion_proof.wtxids.iter().try_for_each(|wtxid| {
            if wtxid.starts_with(prefix) {
                // assert all prefixed transactions are included in completeness proof
                if !completeness_tx_hashes.remove(wtxid) {
                    return Err(ValidationError::RelevantTxNotInProof);
                }
            }
            Ok(())
        })?;

        // assert no other (irrelevant) tx is in completeness proof
        if !completeness_tx_hashes.is_empty() {
            return Err(ValidationError::NonRelevantTxInProof);
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

        Ok(ChainValidityCondition {
            prev_hash: block_header.prev_hash().to_byte_array(),
            block_hash: block_header.block_hash().to_byte_array(),
        })
    }

    fn verify_relevant_tx_list_light_client(
        &self,
        block_header: &<Self::Spec as DaSpec>::BlockHeader,
        blobs: &[<Self::Spec as DaSpec>::BlobTransaction],
        inclusion_proof: <Self::Spec as DaSpec>::InclusionMultiProof,
        completeness_proof: <Self::Spec as DaSpec>::CompletenessProof,
    ) -> Result<<Self::Spec as DaSpec>::ValidityCondition, Self::Error> {
        // create hash set of blobs
        let mut blobs_iter = blobs.iter();

        let mut inclusion_iter = inclusion_proof.wtxids.iter();

        let prefix = self.reveal_light_client_prefix.as_slice();
        // Check starting bytes tx that parsed correctly is in blobs
        let mut completeness_tx_hashes = BTreeSet::new();

        for tx in completeness_proof.iter() {
            let wtxid = tx.compute_wtxid();
            // make sure it starts with the correct prefix
            if !wtxid.as_byte_array().starts_with(prefix) {
                return Err(ValidationError::NonRelevantTxInProof);
            }

            // make sure completeness txs are ordered same in inclusion proof
            // this logic always start seaching from the last found index
            // ordering should be preserved naturally
            let is_found_in_block =
                inclusion_iter.any(|wtxid_inc| wtxid_inc == wtxid.as_byte_array());
            if !is_found_in_block {
                return Err(ValidationError::RelevantTxNotFoundInBlock);
            }

            // it must be parsed correctly
            if let Ok(parsed_tx) = parse_light_client_transaction(tx) {
                match parsed_tx {
                    ParsedLightClientTransaction::Complete(complete) => {
                        if let Some(blob_hash) = complete.get_sig_verified_hash() {
                            let blob = blobs_iter.next();

                            if blob.is_none() {
                                return Err(ValidationError::ValidBlobNotFoundInBlobs);
                            }

                            let blob = blob.unwrap();
                            if blob.hash != blob_hash {
                                return Err(ValidationError::BlobWasTamperedWith);
                            }

                            if complete.public_key != blob.sender.0 {
                                return Err(ValidationError::IncorrectSenderInBlob);
                            }

                            // read the supplied blob from txs
                            let mut blob_content = blob.blob.clone();
                            blob_content.advance(blob_content.total_len());
                            let blob_content = blob_content.accumulator();

                            // assert tx content is not modified
                            let body = decompress_blob(&complete.body);
                            if blob_content != body {
                                return Err(ValidationError::BlobContentWasModified);
                            }
                        }
                    }
                    ParsedLightClientTransaction::Aggregate(aggregate) => {
                        if let Some(blob_hash) = aggregate.get_sig_verified_hash() {
                            let blob = blobs_iter.next();

                            if blob.is_none() {
                                return Err(ValidationError::ValidBlobNotFoundInBlobs);
                            }

                            let blob = blob.unwrap();
                            if blob.hash != blob_hash {
                                return Err(ValidationError::BlobWasTamperedWith);
                            }

                            if aggregate.public_key != blob.sender.0 {
                                return Err(ValidationError::IncorrectSenderInBlob);
                            }

                            // read the supplied blob from txs
                            let mut blob_content = blob.blob.clone();
                            blob_content.advance(blob_content.total_len());
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

            completeness_tx_hashes.insert(wtxid.to_byte_array());
        }

        // assert no extra txs than the ones in the completeness proof are left
        if blobs_iter.next().is_some() {
            return Err(ValidationError::IncorrectCompletenessProof);
        }

        // no prefix bytes left behind completeness proof
        inclusion_proof.wtxids.iter().try_for_each(|wtxid| {
            if wtxid.starts_with(prefix) {
                // assert all prefixed transactions are included in completeness proof
                if !completeness_tx_hashes.remove(wtxid) {
                    return Err(ValidationError::RelevantTxNotInProof);
                }
            }
            Ok(())
        })?;

        // assert no other (irrelevant) tx is in completeness proof
        if !completeness_tx_hashes.is_empty() {
            return Err(ValidationError::NonRelevantTxInProof);
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

        Ok(ChainValidityCondition {
            prev_hash: block_header.prev_hash().to_byte_array(),
            block_hash: block_header.block_hash().to_byte_array(),
        })
    }
}

// impl BitcoinVerifier {
//     fn verify_batch_proofs(&self, batch_proofs: &[ParsedLightClientTransaction]) -> bool {

//         return true;
//     }
// }

#[cfg(test)]
mod tests {

    // Transactions for testing is prepared with 2 leading zeros
    // So verifier takes in [0, 0]

    use core::str::FromStr;

    use bitcoin::block::{Header, Version};
    use bitcoin::hash_types::{TxMerkleNode, WitnessMerkleNode};
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, CompactTarget, ScriptBuf, Witness};
    use sov_rollup_interface::da::DaVerifier;

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
    use crate::verifier::{ChainValidityCondition, ValidationError, WITNESS_COMMITMENT_PREFIX};

    #[test]
    fn correct() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, completeness_proof, txs) = get_mock_data();

        assert!(verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof
            )
            .is_ok());
    }
    #[test]
    fn test_non_segwit_block() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
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
            verifier.verify_relevant_tx_list(
                &header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof
            ),
            Ok(ChainValidityCondition {
                prev_hash: _,
                block_hash: _
            })
        ));
    }

    #[test]
    fn false_coinbase_input_witness_should_fail() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
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
            verifier.verify_relevant_tx_list(
                &header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof
            ),
            Err(ValidationError::IncorrectInclusionProof)
        );
    }

    #[test]
    fn false_coinbase_script_pubkey_should_fail() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
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
            verifier.verify_relevant_tx_list(
                &header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof
            ),
            Err(ValidationError::IncorrectInclusionProof)
        );
    }

    #[test]
    fn false_witness_script_should_fail() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
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
            verifier.verify_relevant_tx_list(
                &header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof
            ),
            Err(ValidationError::NonRelevantTxInProof)
        );
    }

    // verifies it, and then changes the witness and sees that it cannot be verified
    #[test]
    fn different_wtxid_fails_verification() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        assert!(verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof.clone(),
                completeness_proof.clone()
            )
            .is_ok());

        // cahnging the witness txid of coinbase tx to [1; 32] will make it fail
        inclusion_proof.wtxids[0] = [1; 32];

        assert!(verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof.clone(),
                completeness_proof.clone()
            )
            .is_err());

        inclusion_proof.wtxids[0] = [0; 32];

        inclusion_proof.wtxids[1] = [16; 32];

        assert!(verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof
            )
            .is_err());
    }

    #[test]
    fn extra_tx_in_inclusion() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.wtxids.push([5; 32]);

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            ),
            Err(ValidationError::IncorrectInclusionProof)
        );
    }

    #[test]
    fn missing_tx_in_inclusion() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.wtxids.pop();

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            ),
            Err(ValidationError::RelevantTxNotFoundInBlock)
        );
    }

    #[test]
    fn empty_inclusion() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.wtxids.clear();

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            ),
            Err(ValidationError::RelevantTxNotFoundInBlock)
        );
    }

    #[test]
    fn break_order_of_inclusion() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.wtxids.swap(0, 1);

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            ),
            Err(ValidationError::IncorrectInclusionProof)
        );
    }

    #[test]
    fn missing_tx_in_completeness_proof() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, mut completeness_proof, txs) = get_mock_data();

        completeness_proof.pop();

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            ),
            Err(ValidationError::IncorrectCompletenessProof)
        );
    }

    #[test]
    fn empty_completeness_proof() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, mut completeness_proof, txs) = get_mock_data();

        completeness_proof.clear();

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            ),
            Err(ValidationError::IncorrectCompletenessProof)
        );
    }

    #[test]
    fn non_relevant_tx_in_completeness_proof() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, mut completeness_proof, txs) = get_mock_data();

        completeness_proof.push(get_mock_txs().get(1).unwrap().clone().into());

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            ),
            Err(ValidationError::NonRelevantTxInProof)
        );
    }

    #[test]
    fn break_completeness_proof_order() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, mut completeness_proof, mut txs) = get_mock_data();

        completeness_proof.swap(2, 3);
        txs.swap(2, 3);

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            ),
            Err(ValidationError::RelevantTxNotFoundInBlock)
        );
    }

    #[test]
    fn break_rel_tx_order() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, completeness_proof, mut txs) = get_mock_data();

        txs.swap(0, 1);

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            ),
            Err(ValidationError::BlobWasTamperedWith)
        );
    }

    #[test]
    fn break_rel_tx_and_completeness_proof_order() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, mut completeness_proof, mut txs) = get_mock_data();

        txs.swap(0, 1);
        completeness_proof.swap(0, 1);

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            ),
            Err(ValidationError::RelevantTxNotFoundInBlock)
        );
    }

    #[test]
    fn tamper_rel_tx_content() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, completeness_proof, mut txs) = get_mock_data();

        let new_blob = vec![2; 152];

        txs[1] = BlobWithSender::new(new_blob, txs[1].sender.0.clone(), txs[1].hash);
        assert_eq!(
            verifier.verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            ),
            Err(ValidationError::BlobContentWasModified)
        );
    }

    #[test]
    fn tamper_senders() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
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
            verifier.verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            ),
            Err(ValidationError::IncorrectSenderInBlob)
        );
    }

    #[test]
    fn missing_rel_tx() {
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_batch_prover_prefix: vec![1, 1],
            reveal_light_client_prefix: vec![2, 2],
        });

        let (block_header, inclusion_proof, completeness_proof, mut txs) = get_mock_data();

        txs = vec![txs[0].clone(), txs[1].clone(), txs[2].clone()];

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            ),
            Err(ValidationError::ValidBlobNotFoundInBlobs)
        );
    }
}
