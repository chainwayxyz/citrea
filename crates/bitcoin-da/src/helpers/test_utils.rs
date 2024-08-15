use core::str::FromStr;

use bitcoin::block::{Header, Version};
use bitcoin::hash_types::{TxMerkleNode, WitnessMerkleNode};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, Transaction};
use sov_rollup_interface::da::{DaSpec, DaVerifier};

use super::calculate_double_sha256;
use super::parsers::ParsedLightClientTransaction;
use crate::helpers::compression::decompress_blob;
use crate::helpers::parsers::{parse_hex_transaction, parse_transaction};
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

pub(crate) fn get_blob_with_sender(tx: &Transaction) -> BlobWithSender {
    let tx = tx.clone();

    let parsed_transaction = parse_transaction(&tx, "sov-btc").unwrap();

    let (blob, public_key) = match parsed_transaction {
        ParsedLightClientTransaction::Complete(t) => (t.body, t.public_key),
        ParsedLightClientTransaction::Aggregate(t) => {
            panic!("Unexpected tx kind");
        }
        ParsedLightClientTransaction::Chunk(_t) => {
            panic!("Unexpected tx kind");
        }
    };

    // Decompress the blob
    let decompressed_blob = decompress_blob(&blob);

    BlobWithSender::new(
        decompressed_blob,
        public_key,
        calculate_double_sha256(&blob),
    )
}

#[allow(clippy::type_complexity)]
pub(crate) fn get_mock_data() -> (
    <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::BlockHeader, // block header
    <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::InclusionMultiProof, // inclusion proof
    <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::CompletenessProof, // completeness proof
    Vec<<<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::BlobTransaction>, // txs
) {
    unimplemented!("mock tx data")
}

// #[allow(clippy::type_complexity)]
// pub(crate) fn get_mock_data() -> (
//     <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::BlockHeader, // block header
//     <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::InclusionMultiProof, // inclusion proof
//     <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::CompletenessProof, // completeness proof
//     Vec<<<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::BlobTransaction>, // txs
// ) {
//     let header = HeaderWrapper::new(
//         Header {
//             version: Version::from_consensus(536870912),
//             prev_blockhash: BlockHash::from_str(
//                 "6b15a2e4b17b0aabbd418634ae9410b46feaabf693eea4c8621ffe71435d24b0",
//             )
//             .unwrap(),
//             merkle_root: TxMerkleNode::from_str(
//                 "2b84e6a7607e4e383c08af0f3089e460cd52c43ebb7587422064e86402e2f474",
//             )
//             .unwrap(),
//             time: 1723123913,
//             bits: CompactTarget::from_unprefixed_hex("207fffff").unwrap(),
//             nonce: 1,
//         },
//         48,
//         1001,
//         WitnessMerkleNode::from_str(
//             "bfd78d42d5a8ec8fe480a92521806d7648bb3b42d106bb95878609595efbc232",
//         )
//         .unwrap()
//         .to_raw_hash()
//         .to_byte_array(),
//     );

//     let block_txs = get_mock_txs();

//     // parse_transaction(&block_txs[3], "sov-btc").unwrap();

//     // for (id, tx) in block_txs.iter().enumerate() {
//     //     let r = parse_transaction(tx, "sov-btc");
//     //     let err = if let Err(e) = r {
//     //         e
//     //     } else {
//     //         ParserError::ScriptError("OK".to_string())
//     //     };
//     //     dbg!(id, err);
//     // }

//     // relevant txs are on 6, 8, 10, 12 indices
//     let completeness_proof = [
//         4, // complete
//         6, // complete
//         9, // kind 2
//         13, 15, 17, 19, // chain
//         21, 23, 25, 27, // chain
//         29, 31, 33, 35, 37, // chain
//         41, // complete
//         43, 45, 47, // chain
//     ]
//     .into_iter()
//     .map(|i| block_txs[i].clone())
//     .map(Into::into)
//     .collect();
//     // let completeness_proof = [
//     //     block_txs[4].clone(),
//     //     block_txs[6].clone(),
//     //     block_txs[10].clone(),
//     //     block_txs[12].clone(),
//     // ]
//     // .into_iter()
//     // .map(Into::into)
//     // .collect();

//     let mut inclusion_proof = InclusionMultiProof {
//         txids: block_txs
//             .iter()
//             .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
//             .collect(),
//         wtxids: block_txs
//             .iter()
//             .map(|t| t.compute_wtxid().to_byte_array())
//             .collect(),
//         coinbase_tx: block_txs[0].clone().into(),
//     };

//     // Coinbase tx wtxid should be [0u8;32]
//     inclusion_proof.wtxids[0] = [0; 32];

//     let txs: Vec<BlobWithSender> = vec![
//         get_blob_with_sender(&block_txs[6]),
//         get_blob_with_sender(&block_txs[8]),
//         get_blob_with_sender(&block_txs[10]),
//         get_blob_with_sender(&block_txs[12]),
//     ];

//     (header, inclusion_proof, completeness_proof, txs)
// }

pub(crate) fn get_non_segwit_mock_txs() -> Vec<Transaction> {
    // There are no relevant txs
    let txs = std::fs::read_to_string("test_data/mock_non_segwit_txs.txt").unwrap();
    // txs[2] is a non-segwit tx but its txid has the prefix 00
    txs.lines()
        .map(|tx| parse_hex_transaction(tx).unwrap())
        .collect()
}
