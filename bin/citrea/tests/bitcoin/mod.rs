use std::path::PathBuf;

use bitcoin::hashes::Hash;
use bitcoin::Transaction;
use bitcoin_da::helpers::parsers::{parse_relevant_transaction, ParsedTransaction, VerifyParsed};
use bitcoin_da::spec::blob::BlobWithSender;

pub mod batch_prover_test;
pub mod light_client_test;
pub mod rollback;
mod utils;
// pub mod mempool_accept;
pub mod backup;
pub mod bitcoin_service;
pub mod bitcoin_test;
pub mod bitcoin_verifier;
pub mod da_queue;
pub mod fork;
#[cfg(feature = "testing")]
pub mod full_node;
pub mod guest_cycles;
pub mod sequencer_commitments;
pub mod sequencer_test;
pub mod syncing;
pub mod tangerine_related;
pub mod tx_chain;
pub mod tx_propagation;

pub(super) fn get_citrea_path() -> PathBuf {
    std::env::var("CITREA_E2E_TEST_BINARY").map_or_else(
        |_| {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            manifest_dir
                .ancestors()
                .nth(2)
                .expect("Failed to find workspace root")
                .join("target")
                .join("debug")
                .join("citrea")
        },
        PathBuf::from,
    )
}

pub(super) fn get_citrea_cli_path() -> PathBuf {
    std::env::var("CITREA_CLI_E2E_TEST_BINARY").map_or_else(
        |_| {
            let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            manifest_dir
                .ancestors()
                .nth(2)
                .expect("Failed to find workspace root")
                .join("target")
                .join("debug")
                .join("citrea-cli")
        },
        PathBuf::from,
    )
}

fn get_relevant_seqcoms_from_txs(
    txs: Vec<Transaction>,
    reveal_wtxid_prefix: &[u8],
) -> Vec<BlobWithSender> {
    let mut relevant_txs = Vec::new();

    for tx in txs {
        if !tx
            .compute_wtxid()
            .to_byte_array()
            .as_slice()
            .starts_with(reveal_wtxid_prefix)
        {
            continue;
        }

        if let Ok(ParsedTransaction::SequencerCommitment(seq_comm)) =
            parse_relevant_transaction(&tx)
        {
            if let Some(hash) = seq_comm.get_sig_verified_hash() {
                let relevant_tx = BlobWithSender::new(
                    seq_comm.body().to_vec(),
                    seq_comm.public_key().to_vec(),
                    hash,
                    None,
                );

                relevant_txs.push(relevant_tx);
            }
        } else {
            // ignore
        }
    }
    relevant_txs
}
