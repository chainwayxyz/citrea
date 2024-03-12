use std::collections::HashSet;

use bitcoin::hashes::Hash;
use bitcoin::{merkle_tree, Txid};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec, DaVerifier};
use sov_rollup_interface::digest::Digest;
use sov_rollup_interface::zk::ValidityCondition;
use thiserror::Error;

use crate::helpers::builders::decompress_blob;
use crate::helpers::parsers::parse_transaction;
use crate::spec::BitcoinSpec;

pub struct BitcoinVerifier {
    rollup_name: String,
    reveal_tx_id_prefix: Vec<u8>,
}

// TODO: custom errors based on our implementation
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ValidationError {
    InvalidTx,
    InvalidProof,
    InvalidBlock,
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
            block_hash: block_header.prev_hash().to_byte_array(),
        };

        // completeness proof

        // create hash set of blobs
        let mut blobs_iter = blobs.iter();

        let mut prev_index_in_inclusion = 0;

        let prefix = self.reveal_tx_id_prefix.as_slice();
        // Check starting bytes tx that parsed correctly is in blobs
        let mut completeness_tx_hashes = completeness_proof
            .iter()
            .enumerate()
            .map(|(index_completeness, tx)| {
                let tx_hash = tx.txid().to_raw_hash().to_byte_array();

                // make sure it starts with the correct prefix
                assert!(
                    tx_hash.starts_with(prefix),
                    "non-relevant tx found in completeness proof"
                );

                // make sure completeness txs are ordered same in inclusion proof
                // this logic always start seaching from the last found index
                // ordering should be preserved naturally
                let mut is_found_in_block = false;
                for i in prev_index_in_inclusion..inclusion_proof.txs.len() {
                    if inclusion_proof.txs[i] == tx_hash {
                        is_found_in_block = true;
                        prev_index_in_inclusion = i + 1;
                        break;
                    }
                }

                // assert tx is included in inclusion proof, thus in block
                assert!(
                    is_found_in_block,
                    "tx in completeness proof is not found in DA block or order was not preserved"
                );

                // it must be parsed correctly
                if let Ok(parsed_tx) = parse_transaction(tx, &self.rollup_name) {
                    if let Some(blob_hash) = parsed_tx.get_sig_verified_hash() {
                        let blob = blobs_iter.next();

                        assert!(blob.is_some(), "valid blob was not found in blobs");

                        let blob = blob.unwrap();

                        assert_eq!(blob.hash, blob_hash, "blobs was tampered with");

                        assert_eq!(
                            parsed_tx.public_key, blob.sender.0,
                            "incorrect sender in blob"
                        );

                        // decompress the blob
                        let decompressed_blob = decompress_blob(&parsed_tx.body);

                        // read the supplied blob from txs
                        let mut blob_content = blobs[index_completeness].blob.clone();
                        blob_content.advance(blob_content.total_len());
                        let blob_content = blob_content.accumulator();

                        // assert tx content is not modified
                        assert_eq!(blob_content, decompressed_blob, "blob content was modified");
                    }
                }

                tx_hash
            })
            .collect::<HashSet<_>>();

        // assert no extra txs than the ones in the completeness proof are left
        assert!(
            blobs_iter.next().is_none(),
            "completeness proof is incorrect"
        );

        // no prefix bytes left behind completeness proof
        inclusion_proof.txs.iter().for_each(|tx_hash| {
            if tx_hash.starts_with(prefix) {
                // assert all prefixed transactions are included in completeness proof
                assert!(
                    completeness_tx_hashes.remove(tx_hash),
                    "relevant transaction in DA block was not included in completeness proof"
                );
            }
        });

        // assert no other (irrelevant) tx is in completeness proof
        assert!(
            completeness_tx_hashes.is_empty(),
            "non-relevant transaction found in completeness proof"
        );

        let tx_root = block_header.merkle_root().to_raw_hash().to_byte_array();

        // Inclusion proof is all the txs in the block.
        let tx_hashes = inclusion_proof
            .txs
            .iter()
            .map(|tx| Txid::from_slice(tx).unwrap())
            .collect::<Vec<_>>();

        if let Some(root_from_inclusion) = merkle_tree::calculate_root(tx_hashes.into_iter()) {
            let root_from_inclusion = root_from_inclusion.to_raw_hash().to_byte_array();

            // Check that the tx root in the block header matches the tx root in the inclusion proof.
            assert_eq!(root_from_inclusion, tx_root, "inclusion proof is incorrect");

            Ok(validity_condition)
        } else {
            panic!("merkle root couldn't be computed")
        }
    }
}

#[cfg(test)]
mod tests {

    // Transactions for testing is prepared with 2 leading zeros
    // So verifier takes in [0, 0]
    use sov_rollup_interface::da::DaVerifier;

    use super::BitcoinVerifier;
    use crate::helpers::parsers::parse_transaction;
    use crate::helpers::test_utils::{get_mock_data, get_mock_txs};
    use crate::spec::blob::BlobWithSender;
    use crate::spec::RollupParams;

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
    #[should_panic(expected = "inclusion proof is incorrect")]
    fn extra_tx_in_inclusion() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.txs.push([1; 32]);

        verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(
        expected = "tx in completeness proof is not found in DA block or order was not preserved"
    )]
    fn missing_tx_in_inclusion() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.txs.pop();

        verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            )
            .unwrap();
    }

    #[test]
    #[should_panic = "tx in completeness proof is not found in DA block or order was not preserved"]
    fn empty_inclusion() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.txs.clear();

        verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            )
            .unwrap();
    }

    #[test]
    #[should_panic = "inclusion proof is incorrect"]
    fn break_order_of_inclusion() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, mut inclusion_proof, completeness_proof, txs) = get_mock_data();

        inclusion_proof.txs.swap(0, 1);

        verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "completeness proof is incorrect")]
    fn missing_tx_in_completeness_proof() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, inclusion_proof, mut completeness_proof, txs) = get_mock_data();

        completeness_proof.pop();

        verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "completeness proof is incorrect")]
    fn empty_completeness_proof() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, inclusion_proof, mut completeness_proof, txs) = get_mock_data();

        completeness_proof.clear();

        verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "non-relevant tx found in completeness proof")]
    fn non_relevant_tx_in_completeness_proof() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, inclusion_proof, mut completeness_proof, txs) = get_mock_data();

        completeness_proof.push(get_mock_txs().get(1).unwrap().clone());

        verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(
        expected = "tx in completeness proof is not found in DA block or order was not preserved"
    )]
    fn break_completeness_proof_order() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, inclusion_proof, mut completeness_proof, mut txs) = get_mock_data();

        completeness_proof.swap(2, 3);
        txs.swap(2, 3);

        verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "blobs was tampered with")]
    fn break_rel_tx_order() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, inclusion_proof, completeness_proof, mut txs) = get_mock_data();

        txs.swap(0, 1);

        verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            )
            .unwrap();
    }

    #[test]
    #[should_panic = "tx in completeness proof is not found in DA block or order was not preserved"]
    fn break_rel_tx_and_completeness_proof_order() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, inclusion_proof, mut completeness_proof, mut txs) = get_mock_data();

        txs.swap(0, 1);
        completeness_proof.swap(0, 1);

        verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "blob content was modified")]
    fn tamper_rel_tx_content() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, inclusion_proof, completeness_proof, mut txs) = get_mock_data();

        let new_blob = vec![2; 152];

        txs[1] = BlobWithSender::new(new_blob, txs[1].sender.0.clone(), txs[1].hash);

        verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "incorrect sender in blob")]
    fn tamper_senders() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, inclusion_proof, completeness_proof, mut txs) = get_mock_data();

        txs[1] = BlobWithSender::new(
            parse_transaction(&completeness_proof[1], "sov-btc")
                .unwrap()
                .body,
            vec![2; 33],
            txs[1].hash,
        );

        verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            )
            .unwrap();
    }

    #[test]
    #[should_panic(expected = "valid blob was not found in blobs")]
    fn missing_rel_tx() {
        let verifier = BitcoinVerifier::new(RollupParams {
            rollup_name: "sov-btc".to_string(),
            reveal_tx_id_prefix: vec![0, 0],
        });

        let (block_header, inclusion_proof, completeness_proof, mut txs) = get_mock_data();

        txs = vec![txs[0].clone(), txs[1].clone(), txs[2].clone()];

        verifier
            .verify_relevant_tx_list(
                &block_header,
                txs.as_slice(),
                inclusion_proof,
                completeness_proof,
            )
            .unwrap();
    }
}
