//! Best-effort mempool recovery across graceful restarts.

use std::fs;
use std::io::ErrorKind;

use anyhow::Context;
use reth_primitives::transaction::SignedTransaction;
use reth_primitives::TransactionSigned;
use reth_transaction_pool::{EthPooledTransaction, PoolTransaction};
use tracing::{info, warn};

use super::CitreaMempool;

impl CitreaMempool {
    /// Writes pending and queued transactions to the snapshot file.
    pub(crate) fn save(&self) -> anyhow::Result<()> {
        let pool_transactions = self.all_transactions();
        let mut transactions = pool_transactions
            .pending
            .iter()
            .chain(&pool_transactions.queued)
            .collect::<Vec<_>>();
        // Restore each sender's transactions in nonce order.
        transactions.sort_unstable_by_key(|tx| (tx.sender(), tx.nonce()));
        let transactions = transactions
            .into_iter()
            .map(|tx| tx.transaction.clone_into_consensus().into_inner())
            .collect::<Vec<TransactionSigned>>();
        let mut data = Vec::new();
        alloy_rlp::encode_list(&transactions, &mut data);

        // Write and rename, so an interrupted save cannot leave a truncated file.
        let temporary_path = self.snapshot_path.with_extension("rlp.tmp");
        fs::write(&temporary_path, data).context("Failed to write mempool snapshot")?;
        fs::rename(&temporary_path, &self.snapshot_path)
            .context("Failed to replace mempool snapshot")?;
        info!(transactions = transactions.len(), "Saved mempool");
        Ok(())
    }

    /// Re-adds saved transactions, revalidating them against the current state. The file is
    /// removed after restoration finishes.
    pub(crate) async fn restore(&self) -> anyhow::Result<()> {
        let data = match fs::read(&self.snapshot_path) {
            Ok(data) => data,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err).context("Failed to read mempool snapshot"),
        };
        let transactions: Vec<TransactionSigned> =
            alloy_rlp::decode_exact(data).context("Failed to decode mempool snapshot")?;

        let mut restored = 0;
        for transaction in transactions {
            let Some(transaction) = transaction
                .try_into_recovered()
                .ok()
                .and_then(|tx| EthPooledTransaction::try_from_consensus(tx).ok())
            else {
                warn!("Skipping invalid transaction in mempool snapshot");
                continue;
            };
            match self.add_external_transaction(transaction).await {
                Ok(_) => restored += 1,
                Err(err) => warn!(%err, "Skipping rejected transaction in mempool snapshot"),
            }
        }
        fs::remove_file(&self.snapshot_path).context("Failed to remove mempool snapshot")?;
        info!(restored, "Restored mempool");
        Ok(())
    }
}
