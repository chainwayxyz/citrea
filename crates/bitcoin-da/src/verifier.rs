use std::collections::HashSet;

use bitcoin::hashes::{sha256d, Hash};
use bitcoin::{merkle_tree, Txid};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec, DaVerifier};
use sov_rollup_interface::digest::Digest;
use sov_rollup_interface::zk::ValidityCondition;
use thiserror::Error;

use crate::helpers::compression::decompress_blob;
use crate::helpers::parsers::parse_transaction;
use crate::spec::BitcoinSpec;

pub struct BitcoinVerifier {
    rollup_name: String,
    reveal_tx_id_prefix: Vec<u8>,
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
            rollup_name: params.rollup_name,
            reveal_tx_id_prefix: params.reveal_tx_id_prefix,
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
        let validity_condition = ChainValidityCondition {
            prev_hash: block_header.prev_hash().to_byte_array(),
            block_hash: block_header.block_hash().to_byte_array(),
        };

        // check that wtxid's of transactions in completeness proof are included in the InclusionMultiProof
        // and are in the same order as in the completeness proof
        let mut iter = inclusion_proof.wtxids.iter();
        completeness_proof
            .iter()
            .all(|tx| iter.any(|&y| y == tx.wtxid().to_byte_array()));

        // verify that one of the outputs of the coinbase transaction has script pub key starting with 0x6a24aa21a9ed,
        // and the rest of the script pub key is the commitment of witness data.
        if !completeness_proof.is_empty() {
            let coinbase_tx = &inclusion_proof.coinbase_tx;
            // If there are more than one scriptPubKey matching the pattern,
            // the one with highest output index is assumed to be the commitment.
            // That  is why the iterator is reversed.
            let commitment_idx = coinbase_tx.output.iter().rev().position(|output| {
                output
                    .script_pubkey
                    .to_bytes()
                    .starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed])
            });
            match commitment_idx {
                // If commitmet does not exist
                None => {
                    // Relevant txs should be empty if there is no wtiness data because data is inscribed in the witness
                    if !blobs.is_empty() {
                        return Err(ValidationError::InvalidBlock);
                    }
                    // Check if all the wtxids are equal to txids
                    for (wtxid, txid) in inclusion_proof
                        .wtxids
                        .iter()
                        .zip(inclusion_proof.txids.iter())
                    {
                        if wtxid != txid {
                            return Err(ValidationError::InvalidSegWitCommitment);
                        }
                    }
                }
                Some(mut commitment_idx) => {
                    let wtxids = inclusion_proof
                        .wtxids
                        .iter()
                        .copied()
                        .map(Txid::from_byte_array);

                    let merkle_root = merkle_tree::calculate_root(wtxids).unwrap();

                    let input_witness_value = coinbase_tx.input[0].witness.iter().next().unwrap();

                    let mut vec_merkle = merkle_root.to_byte_array().to_vec();

                    vec_merkle.extend_from_slice(input_witness_value);

                    // check with sha256(sha256(<merkle root><witness value>))
                    let commitment = sha256d::Hash::hash(&vec_merkle);

                    // check if the commitment is correct
                    // on signet there is an additional commitment after the segwit commitment
                    // so we check only the first 32 bytes after commitment header (bytes [2, 5])
                    commitment_idx = coinbase_tx.output.len() - commitment_idx - 1; // The index is reversed
                    let script_pubkey = coinbase_tx.output[commitment_idx].script_pubkey.to_bytes();
                    if script_pubkey[6..38] != *commitment.as_byte_array() {
                        return Err(ValidationError::NonMatchingScript);
                    }
                }
            }
        }

        // create hash set of blobs
        let mut blobs_iter = blobs.iter();

        let mut inclusion_iter = inclusion_proof.txids.iter();

        let prefix = self.reveal_tx_id_prefix.as_slice();
        // Check starting bytes tx that parsed correctly is in blobs
        let mut completeness_tx_hashes = HashSet::new();

        for (index_completeness, tx) in completeness_proof.iter().enumerate() {
            let txid = tx.txid().to_byte_array();

            // make sure it starts with the correct prefix
            if !txid.starts_with(prefix) {
                return Err(ValidationError::NonRelevantTxInProof);
            }

            // make sure completeness txs are ordered same in inclusion proof
            // this logic always start seaching from the last found index
            // ordering should be preserved naturally
            let is_found_in_block = inclusion_iter.any(|&txid_in_proof| txid_in_proof == txid);

            // assert tx is included in inclusion proof, thus in block
            if !is_found_in_block {
                return Err(ValidationError::RelevantTxNotFoundInBlock);
            }

            // it must be parsed correctly
            if let Ok(parsed_tx) = parse_transaction(tx, &self.rollup_name) {
                if let Some(blob_hash) = parsed_tx.get_sig_verified_hash() {
                    let blob = blobs_iter.next();

                    if blob.is_none() {
                        return Err(ValidationError::ValidBlobNotFoundInBlobs);
                    }

                    let blob = blob.unwrap();
                    if blob.hash != blob_hash {
                        return Err(ValidationError::BlobWasTamperedWith);
                    }

                    if parsed_tx.public_key != blob.sender.0 {
                        return Err(ValidationError::IncorrectSenderInBlob);
                    }

                    // decompress the blob
                    let decompressed_blob = decompress_blob(&parsed_tx.body);

                    // read the supplied blob from txs
                    let mut blob_content = blobs[index_completeness].blob.clone();
                    blob_content.advance(blob_content.total_len());
                    let blob_content = blob_content.accumulator();

                    // assert tx content is not modified
                    if blob_content != decompressed_blob {
                        return Err(ValidationError::BlobContentWasModified);
                    }
                }
            }

            completeness_tx_hashes.insert(txid);
        }

        // assert no extra txs than the ones in the completeness proof are left
        if blobs_iter.next().is_some() {
            return Err(ValidationError::IncorrectCompletenessProof);
        }

        // no prefix bytes left behind completeness proof
        inclusion_proof.txids.iter().try_for_each(|tx_hash| {
            if tx_hash.starts_with(prefix) {
                // assert all prefixed transactions are included in completeness proof
                if !completeness_tx_hashes.remove(tx_hash) {
                    return Err(ValidationError::RelevantTxNotInProof);
                }
            }
            Ok(())
        })?;

        // assert no other (irrelevant) tx is in completeness proof
        if !completeness_tx_hashes.is_empty() {
            return Err(ValidationError::NonRelevantTxInProof);
        }

        let tx_root = block_header.merkle_root();

        // Inclusion proof is all the txs in the block.
        let tx_hashes = inclusion_proof
            .txids
            .iter()
            .map(|tx| Txid::from_slice(tx).unwrap())
            .collect::<Vec<_>>();

        if let Some(root_from_inclusion) = merkle_tree::calculate_root(tx_hashes.into_iter()) {
            let root_from_inclusion = root_from_inclusion.to_raw_hash().to_byte_array();

            // Check that the tx root in the block header matches the tx root in the inclusion proof.
            if root_from_inclusion != tx_root {
                return Err(ValidationError::IncorrectInclusionProof);
            }

            Ok(validity_condition)
        } else {
            Err(ValidationError::FailedToCalculateMerkleRoot)
        }
    }
}

#[cfg(test)]
mod tests {

    // Transactions for testing is prepared with 2 leading zeros
    // So verifier takes in [0, 0]

    use core::str::FromStr;

    use bitcoin::block::{Header, Version};
    use bitcoin::hash_types::{TxMerkleNode, WitnessMerkleNode};
    use bitcoin::hashes::Hash;
    use bitcoin::string::FromHexStr;
    use bitcoin::{BlockHash, CompactTarget, ScriptBuf, Witness};
    use sov_rollup_interface::da::DaVerifier;

    use super::BitcoinVerifier;
    use crate::helpers::parsers::parse_transaction;
    use crate::helpers::test_utils::{
        get_blob_with_sender, get_mock_data, get_mock_txs, get_non_segwit_mock_txs,
    };
    use crate::spec::blob::BlobWithSender;
    use crate::spec::header::HeaderWrapper;
    use crate::spec::proof::InclusionMultiProof;
    use crate::spec::transaction::TransactionWrapper;
    use crate::spec::RollupParams;
    use crate::verifier::{ChainValidityCondition, ValidationError};

    #[test]
    fn correct() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
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
                bits: CompactTarget::from_hex_str_no_prefix("207fffff").unwrap(),
                nonce: 0,
            },
            6,
            2,
            WitnessMerkleNode::from_str(
                "a8b25755ed6e2f1df665b07e751f6acc1ff4e1ec765caa93084176e34fa5ad71",
            )
            .unwrap(),
        );

        let block_txs = get_non_segwit_mock_txs();
        let block_txs: Vec<TransactionWrapper> = block_txs.into_iter().map(Into::into).collect();

        // block does not have any segwit txs
        let idx = block_txs[0].output.iter().position(|output| {
            output
                .script_pubkey
                .to_bytes()
                .starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed])
        });
        assert!(idx.is_none());

        // tx with txid 00... is not relevant is in this proof
        // only used so the completeness proof is not empty
        let completeness_proof = vec![];

        let inclusion_proof = InclusionMultiProof {
            txids: block_txs
                .iter()
                .map(|t| t.txid().to_raw_hash().to_byte_array())
                .collect(),
            wtxids: block_txs
                .iter()
                .map(|t| t.wtxid().to_byte_array())
                .collect(),
            coinbase_tx: block_txs[0].clone(),
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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let header = HeaderWrapper::new(
            Header {
                version: Version::from_consensus(536870912),
                prev_blockhash: BlockHash::from_str(
                    "6b15a2e4b17b0aabbd418634ae9410b46feaabf693eea4c8621ffe71435d24b0",
                )
                .unwrap(),
                merkle_root: TxMerkleNode::from_str(
                    "7750076b3b5498aad3e2e7da55618c66394d1368dc08f19f0b13d1e5b83ae056",
                )
                .unwrap(),
                time: 1694177029,
                bits: CompactTarget::from_hex_str_no_prefix("207fffff").unwrap(),
                nonce: 0,
            },
            13,
            2,
            WitnessMerkleNode::from_str(
                "a8b25755ed6e2f1df665b07e751f6acc1ff4e1ec765caa93084176e34fa5ad71",
            )
            .unwrap(),
        );

        let block_txs = get_mock_txs();
        let mut block_txs: Vec<TransactionWrapper> =
            block_txs.into_iter().map(Into::into).collect();

        block_txs[0].input[0].witness = Witness::from_slice(&[vec![1u8; 32]]);

        // relevant txs are on 6, 8, 10, 12 indices
        let completeness_proof = [
            block_txs[6].clone(),
            block_txs[8].clone(),
            block_txs[10].clone(),
            block_txs[12].clone(),
        ]
        .into_iter()
        .map(Into::into)
        .collect();

        let mut inclusion_proof = InclusionMultiProof {
            txids: block_txs
                .iter()
                .map(|t| t.txid().to_raw_hash().to_byte_array())
                .collect(),
            wtxids: block_txs
                .iter()
                .map(|t| t.wtxid().to_byte_array())
                .collect(),
            coinbase_tx: block_txs[0].clone(),
        };

        // Coinbase tx wtxid should be [0u8;32]
        inclusion_proof.wtxids[0] = [0; 32];

        let txs: Vec<BlobWithSender> = vec![
            get_blob_with_sender(&block_txs[6]),
            get_blob_with_sender(&block_txs[8]),
            get_blob_with_sender(&block_txs[10]),
            get_blob_with_sender(&block_txs[12]),
        ];

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof
            ),
            Err(ValidationError::NonMatchingScript)
        );
    }

    #[test]
    fn false_coinbase_script_pubkey_should_fail() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let header = HeaderWrapper::new(
            Header {
                version: Version::from_consensus(536870912),
                prev_blockhash: BlockHash::from_str(
                    "6b15a2e4b17b0aabbd418634ae9410b46feaabf693eea4c8621ffe71435d24b0",
                )
                .unwrap(),
                merkle_root: TxMerkleNode::from_str(
                    "7750076b3b5498aad3e2e7da55618c66394d1368dc08f19f0b13d1e5b83ae056",
                )
                .unwrap(),
                time: 1694177029,
                bits: CompactTarget::from_hex_str_no_prefix("207fffff").unwrap(),
                nonce: 0,
            },
            13,
            2,
            WitnessMerkleNode::from_str(
                "a8b25755ed6e2f1df665b07e751f6acc1ff4e1ec765caa93084176e34fa5ad71",
            )
            .unwrap(),
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
                    .starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed])
            })
            .unwrap();

        // the 7th byte of script pubkey is changed from 104 to 105
        block_txs[0].output[idx].script_pubkey = ScriptBuf::from_bytes(vec![
            106, 36, 170, 33, 169, 237, 105, 181, 249, 155, 21, 242, 213, 115, 55, 123, 70, 108,
            15, 173, 14, 106, 243, 231, 186, 128, 75, 251, 178, 9, 24, 228, 200, 177, 144, 89, 95,
            182,
        ]);

        // relevant txs are on 6, 8, 10, 12 indices
        let completeness_proof = [
            block_txs[6].clone(),
            block_txs[8].clone(),
            block_txs[10].clone(),
            block_txs[12].clone(),
        ]
        .into_iter()
        .map(Into::into)
        .collect();

        let mut inclusion_proof = InclusionMultiProof {
            txids: block_txs
                .iter()
                .map(|t| t.txid().to_raw_hash().to_byte_array())
                .collect(),
            wtxids: block_txs
                .iter()
                .map(|t| t.wtxid().to_byte_array())
                .collect(),
            coinbase_tx: block_txs[0].clone(),
        };

        // Coinbase tx wtxid should be [0u8;32]
        inclusion_proof.wtxids[0] = [0; 32];

        let txs: Vec<BlobWithSender> = vec![
            get_blob_with_sender(&block_txs[6]),
            get_blob_with_sender(&block_txs[8]),
            get_blob_with_sender(&block_txs[10]),
            get_blob_with_sender(&block_txs[12]),
        ];

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof
            ),
            Err(ValidationError::NonMatchingScript)
        );
    }

    #[test]
    fn false_witness_script_should_fail() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let header = HeaderWrapper::new(
            Header {
                version: Version::from_consensus(536870912),
                prev_blockhash: BlockHash::from_str(
                    "6b15a2e4b17b0aabbd418634ae9410b46feaabf693eea4c8621ffe71435d24b0",
                )
                .unwrap(),
                merkle_root: TxMerkleNode::from_str(
                    "7750076b3b5498aad3e2e7da55618c66394d1368dc08f19f0b13d1e5b83ae056",
                )
                .unwrap(),
                time: 1694177029,
                bits: CompactTarget::from_hex_str_no_prefix("207fffff").unwrap(),
                nonce: 0,
            },
            13,
            2,
            WitnessMerkleNode::from_str(
                "a8b25755ed6e2f1df665b07e751f6acc1ff4e1ec765caa93084176e34fa5ad71",
            )
            .unwrap(),
        );

        let block_txs = get_mock_txs();
        let mut block_txs: Vec<TransactionWrapper> =
            block_txs.into_iter().map(Into::into).collect();

        // This is the changed witness of the 6th tx, the first byte of script is changed from 32 to 33
        // This creates a different wtxid, thus the verification should fail
        let changed_witness: Vec<Vec<u8>> = vec![
            vec![
                81, 88, 52, 28, 35, 77, 19, 30, 98, 146, 2, 231, 141, 193, 70, 58, 24, 252, 94,
                184, 169, 253, 234, 219, 176, 172, 224, 112, 128, 144, 70, 134, 16, 75, 6, 112,
                182, 76, 230, 26, 239, 154, 8, 219, 123, 102, 210, 203, 74, 187, 185, 45, 3, 35,
                94, 95, 64, 209, 195, 34, 66, 246, 47, 239,
            ],
            vec![
                33, 113, 162, 71, 125, 67, 165, 112, 30, 91, 79, 0, 158, 242, 217, 32, 194, 150,
                158, 249, 221, 71, 241, 82, 79, 243, 107, 93, 250, 8, 122, 90, 29, 172, 0, 99, 1,
                1, 7, 115, 111, 118, 45, 98, 116, 99, 1, 2, 64, 204, 75, 35, 210, 203, 62, 34, 178,
                197, 122, 89, 242, 64, 136, 118, 79, 57, 247, 183, 137, 132, 126, 152, 59, 158,
                233, 206, 118, 130, 87, 140, 43, 125, 189, 244, 56, 78, 35, 12, 148, 43, 145, 174,
                92, 230, 177, 186, 51, 88, 127, 84, 159, 237, 238, 77, 25, 229, 79, 243, 168, 229,
                70, 1, 232, 1, 3, 33, 2, 88, 141, 32, 42, 252, 193, 238, 74, 181, 37, 76, 120, 71,
                236, 37, 185, 161, 53, 187, 218, 15, 43, 198, 158, 225, 167, 20, 116, 159, 215,
                125, 201, 1, 4, 3, 140, 4, 3, 0, 76, 196, 27, 123, 1, 248, 69, 199, 134, 177, 14,
                144, 99, 139, 92, 216, 128, 35, 8, 24, 35, 176, 108, 32, 185, 0, 64, 64, 16, 82,
                134, 7, 56, 167, 198, 205, 96, 199, 53, 143, 88, 17, 88, 187, 247, 230, 188, 146,
                199, 57, 30, 254, 87, 237, 64, 197, 147, 216, 162, 224, 152, 57, 150, 149, 38, 166,
                136, 221, 108, 223, 62, 19, 150, 90, 236, 168, 89, 44, 83, 183, 232, 187, 206, 143,
                137, 234, 84, 146, 177, 70, 242, 67, 179, 229, 165, 3, 94, 174, 81, 199, 235, 230,
                184, 188, 60, 171, 3, 72, 123, 113, 167, 153, 1, 22, 216, 181, 175, 220, 83, 55,
                14, 149, 187, 22, 167, 192, 173, 189, 132, 137, 116, 155, 150, 173, 21, 174, 68,
                140, 43, 227, 187, 51, 47, 125, 195, 155, 109, 150, 123, 2, 111, 159, 89, 26, 249,
                111, 54, 105, 241, 247, 201, 204, 123, 29, 208, 71, 162, 195, 146, 187, 209, 69,
                218, 241, 17, 66, 119, 98, 83, 228, 32, 245, 236, 204, 22, 154, 251, 85, 105, 61,
                15, 235, 194, 127, 13, 177, 89, 3, 104,
            ],
            vec![
                193, 113, 162, 71, 125, 67, 165, 112, 30, 91, 79, 0, 158, 242, 217, 32, 194, 150,
                158, 249, 221, 71, 241, 82, 79, 243, 107, 93, 250, 8, 122, 90, 29,
            ],
        ];

        block_txs[6].input[0].witness = Witness::from_slice(&changed_witness);
        // relevant txs are on 6, 8, 10, 12 indices
        let completeness_proof = [
            block_txs[6].clone(),
            block_txs[8].clone(),
            block_txs[10].clone(),
            block_txs[12].clone(),
        ]
        .into_iter()
        .map(Into::into)
        .collect();

        let mut inclusion_proof = InclusionMultiProof {
            txids: block_txs
                .iter()
                .map(|t| t.txid().to_raw_hash().to_byte_array())
                .collect(),
            wtxids: block_txs
                .iter()
                .map(|t| t.wtxid().to_byte_array())
                .collect(),
            coinbase_tx: block_txs[0].clone(),
        };

        // Coinbase tx wtxid should be [0u8;32]
        inclusion_proof.wtxids[0] = [0; 32];

        let txs: Vec<BlobWithSender> = vec![
            get_blob_with_sender(&block_txs[6]),
            get_blob_with_sender(&block_txs[8]),
            get_blob_with_sender(&block_txs[10]),
            get_blob_with_sender(&block_txs[12]),
        ];

        assert_eq!(
            verifier.verify_relevant_tx_list(
                &header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof
            ),
            Err(ValidationError::NonMatchingScript)
        );
    }

    // verifies it, and then changes the witness and sees that it cannot be verified
    #[test]
    fn different_wtxid_fails_verification() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.txids.push([1; 32]);

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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.txids.pop();

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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.txids.clear();

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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.txids.swap(0, 1);

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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, inclusion_proof, completeness_proof, mut txs) = get_mock_data();
        let tx1 = &completeness_proof[1];
        txs[1] = BlobWithSender::new(
            parse_transaction(tx1, "sov-btc").unwrap().body,
            vec![2; 33],
            txs[1].hash,
        );

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
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
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
