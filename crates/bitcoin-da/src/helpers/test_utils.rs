use core::str::FromStr;

use bitcoin::block::{Header, Version};
use bitcoin::hash_types::{TxMerkleNode, WitnessMerkleNode};
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::string::FromHexStr;
use bitcoin::{BlockHash, CompactTarget, Transaction};
use sov_rollup_interface::da::{DaSpec, DaVerifier};

use crate::helpers::compression::decompress_blob;
use crate::helpers::parsers::{parse_hex_transaction, parse_transaction};
use crate::spec::blob::BlobWithSender;
use crate::spec::header::HeaderWrapper;
use crate::spec::proof::InclusionMultiProof;
use crate::verifier::BitcoinVerifier;

pub(crate) fn get_mock_txs() -> Vec<Transaction> {
    // relevant txs are on 6, 8, 10, 12 indices
    let txs = std::fs::read_to_string("test_data/mock_txs.txt").unwrap();

    txs.lines()
        .map(|tx| parse_hex_transaction(tx).unwrap())
        .collect()
}

pub(crate) fn get_blob_with_sender(tx: &Transaction) -> BlobWithSender {
    let tx = tx.clone();

    let parsed_inscription = parse_transaction(&tx, "sov-btc").unwrap();

    let blob = parsed_inscription.body;

    // Decompress the blob
    let decompressed_blob = decompress_blob(&blob);

    BlobWithSender::new(
        decompressed_blob,
        parsed_inscription.public_key,
        sha256d::Hash::hash(&blob).to_byte_array(),
    )
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
        coinbase_tx: block_txs[0].clone().into(),
    };

    // Coinbase tx wtxid should be [0u8;32]
    inclusion_proof.wtxids[0] = [0; 32];

    let txs: Vec<BlobWithSender> = vec![
        get_blob_with_sender(&block_txs[6]),
        get_blob_with_sender(&block_txs[8]),
        get_blob_with_sender(&block_txs[10]),
        get_blob_with_sender(&block_txs[12]),
    ];

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
