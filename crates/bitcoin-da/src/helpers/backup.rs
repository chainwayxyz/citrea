//! Backup DaTxs to disk.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use bitcoin::{consensus, Transaction};

use crate::helpers::TransactionKind;
use crate::tx_signer::SignedTxPair;

fn transaction_kind_to_backup_name(kind: &TransactionKind) -> &str {
    match kind {
        TransactionKind::Complete => "complete_zk_proof",
        TransactionKind::SequencerCommitment => "sequencer_commitment",
        TransactionKind::BatchProofMethodId => "method_id_update",
        TransactionKind::Chunks => "chunks",
        TransactionKind::Aggregate => "aggregate",
        TransactionKind::Unknown(_) => "unknown",
    }
}

/// Save DaTxs on disk.
pub(crate) fn backup_txs_to_file(path: &Path, txs: &[SignedTxPair]) -> anyhow::Result<()> {
    if let Some(tx) = txs.first() {
        match &tx.kind {
            TransactionKind::Complete
            | TransactionKind::BatchProofMethodId
            | TransactionKind::SequencerCommitment => {
                if txs.len() != 1 {
                    return Err(anyhow::anyhow!(
                        "Expected exactly 2 transactions for {:?}, got {}",
                        tx.kind,
                        txs.len()
                    ));
                }

                backup_complete_txs(
                    path,
                    &tx.as_raw_txs(),
                    transaction_kind_to_backup_name(&tx.kind),
                )?
            }
            TransactionKind::Aggregate | TransactionKind::Chunks => backup_chunked_txs(path, txs)?,
            TransactionKind::Unknown(_) => unimplemented!(),
        }
    }
    Ok(())
}

/// Save DaTxs::Complete on disk.
fn backup_complete_txs(path: &Path, raw_txs: &[&Vec<u8>; 2], name: &str) -> anyhow::Result<()> {
    let commit_tx: Transaction = consensus::deserialize(raw_txs[0])?;
    let reveal_tx: Transaction = consensus::deserialize(raw_txs[1])?;

    let file_path = path.join(format!(
        "{}_inscription_commit_id_{}_reveal_id_{}.txs",
        name,
        commit_tx.compute_txid(),
        reveal_tx.compute_txid()
    ));

    let file = File::create(file_path)?;
    let mut writer = BufWriter::new(&file);
    writer.write_all(format!("commit {}\n", commit_tx.compute_txid()).as_bytes())?;
    writer.write_all(hex::encode(raw_txs[0].as_slice()).as_bytes())?;
    writer.write_all(b"\n")?;
    writer.write_all(format!("reveal {}\n", reveal_tx.compute_txid()).as_bytes())?;
    writer.write_all(hex::encode(raw_txs[1].as_slice()).as_bytes())?;
    writer.flush()?;
    Ok(())
}

/// Save DaTxs::Chunked on disk.
fn backup_chunked_txs(path: &Path, txs: &[SignedTxPair]) -> anyhow::Result<()> {
    let last_pair = txs
        .last()
        .expect("Chunked txs to have at least one pair")
        .as_raw_txs();
    let aggr_commit: Transaction = consensus::deserialize(last_pair[0])?;
    let aggr_reveal: Transaction = consensus::deserialize(last_pair[1])?;

    let file_path = path.join(format!(
        "chunked_inscription_commit_id_{}_reveal_id_{}.txs",
        aggr_commit.compute_txid(),
        aggr_reveal.compute_txid(),
    ));

    let file = File::create(file_path)?;
    let mut writer = BufWriter::new(&file);

    for (idx, tx_pair) in txs[..txs.len() - 1].iter().enumerate() {
        let raw_txs = tx_pair.as_raw_txs();
        let commit_tx: Transaction = consensus::deserialize(raw_txs[0])?;
        let reveal_tx: Transaction = consensus::deserialize(raw_txs[1])?;

        writer.write_all(
            format!("chunk {} commit {}\n", idx + 1, commit_tx.compute_txid()).as_bytes(),
        )?;
        writer.write_all(hex::encode(raw_txs[0]).as_bytes())?;
        writer.write_all(b"\n")?;
        writer.write_all(
            format!("chunk {} reveal {}\n", idx + 1, reveal_tx.compute_txid()).as_bytes(),
        )?;
        writer.write_all(hex::encode(raw_txs[1]).as_bytes())?;
        writer.write_all(b"\n")?;
    }

    writer.write_all(format!("aggregate commit {}\n", aggr_commit.compute_txid()).as_bytes())?;
    writer.write_all(hex::encode(last_pair[0]).as_bytes())?;
    writer.write_all(b"\n")?;
    writer.write_all(format!("aggregate reveal {}\n", aggr_reveal.compute_txid()).as_bytes())?;
    writer.write_all(hex::encode(last_pair[1]).as_bytes())?;
    writer.flush()?;
    Ok(())
}
