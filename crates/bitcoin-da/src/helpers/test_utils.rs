use core::str::FromStr;

use bitcoin::block::{Header, Version};
use bitcoin::hash_types::{TxMerkleNode, WitnessMerkleNode};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, Transaction};
use sov_rollup_interface::da::{DaSpec, DaVerifier};

use super::parsers::{parse_batch_proof_transaction, ParserError};
use super::{calculate_sha256, merkle_tree};
use crate::helpers::parsers::parse_hex_transaction;
use crate::spec::blob::BlobWithSender;
use crate::spec::header::HeaderWrapper;
use crate::spec::proof::InclusionMultiProof;
use crate::verifier::BitcoinVerifier;

pub(crate) fn get_mock_txs() -> Vec<Transaction> {
    // relevant txs are on 6, 8, 10, 12 indices
    let txs = include_str!("../../test_data/mock_txs.txt");

    txs.lines()
        .map(|tx| parse_hex_transaction(tx).unwrap())
        .collect()
}

pub(crate) fn get_blob_with_sender(tx: &Transaction) -> Result<BlobWithSender, ParserError> {
    let tx = tx.clone();

    let parsed_transaction = parse_batch_proof_transaction(&tx)?;

    let (blob, public_key) = match parsed_transaction {
        super::parsers::ParsedBatchProofTransaction::SequencerCommitment(seq_com) => {
            (seq_com.body, seq_com.public_key)
        }
    };

    Ok(BlobWithSender::new(
        blob.clone(),
        public_key,
        calculate_sha256(&blob),
    ))
}

#[allow(clippy::type_complexity)]
pub(crate) fn get_mock_data() -> (
    <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::BlockHeader, // block header
    <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::InclusionMultiProof, // inclusion proof
    <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::CompletenessProof, // completeness proof
    Vec<<<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::BlobTransaction>, // txs
) {
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

    let relevant_txs_indices = [4, 6, 18, 28, 34];

    let completeness_proof = relevant_txs_indices
        .into_iter()
        .map(|i| block_txs[i].clone())
        .map(Into::into)
        .collect();

    let tree = merkle_tree::BitcoinMerkleTree::new(
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
        coinbase_tx: block_txs[0].clone().into(),
        coinbase_merkle_proof: tree.get_idx_path(0),
    };

    // Coinbase tx wtxid should be [0u8;32]
    inclusion_proof.wtxids[0] = [0; 32];

    let txs: Vec<BlobWithSender> = relevant_txs_indices
        .into_iter()
        .filter_map(|i| get_blob_with_sender(&block_txs[i]).ok())
        .collect();

    (header, inclusion_proof, completeness_proof, txs)
}

pub(crate) fn get_non_segwit_mock_txs() -> Vec<Transaction> {
    // There are no relevant txs
    let txs = std::fs::read_to_string("test_data/mock_non_segwit_txs.txt").unwrap();
    // txs[2] is a non-segwit tx but its txid has the prefix 00
    txs.lines()
        .map(|tx| parse_hex_transaction(tx).unwrap())
        .collect()
}
