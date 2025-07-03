use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::consensus::encode;
use bitcoin::{Transaction, Txid};
use bitcoincore_rpc::json::SignRawTransactionInput;
use bitcoincore_rpc::{Client, RpcApi};
use tracing::trace;

use crate::error::BitcoinServiceError;
use crate::helpers::builders::body_builders::DaTxs;
use crate::helpers::builders::TxWithId;
use crate::helpers::TransactionKind;

pub(crate) type Result<T> = std::result::Result<T, BitcoinServiceError>;

#[derive(Debug)]
pub(crate) struct HexWithId {
    hex: Vec<u8>,
    id: Txid,
}

/// Pair of commit/reveal signed transactions
#[derive(Debug)]
pub(crate) struct SignedTxPair {
    commit: HexWithId,
    reveal: HexWithId,
    pub kind: TransactionKind,
}

impl SignedTxPair {
    pub fn as_raw_txs(&self) -> [&Vec<u8>; 2] {
        [&self.commit.hex, &self.reveal.hex]
    }

    pub fn as_txids(&self) -> [Txid; 2] {
        [self.commit.id, self.reveal.id]
    }

    // Pre-computed reveal txid
    pub fn reveal_txid(&self) -> Txid {
        self.reveal.id
    }
}

#[derive(Debug)]
pub(crate) struct TxSigner {
    client: Arc<Client>,
}

impl TxSigner {
    pub fn new(client: Arc<Client>) -> Self {
        Self { client }
    }

    pub(crate) async fn sign_da_txs(&self, da_txs: DaTxs) -> Result<Vec<SignedTxPair>> {
        let queued_txs = match da_txs {
            DaTxs::Complete { commit, reveal } => {
                vec![
                    self.sign_complete_transaction(commit, reveal, TransactionKind::Complete)
                        .await?,
                ]
            }
            DaTxs::SequencerCommitment { commit, reveal } => {
                vec![
                    self.sign_complete_transaction(
                        commit,
                        reveal,
                        TransactionKind::SequencerCommitment,
                    )
                    .await?,
                ]
            }
            DaTxs::BatchProofMethodId { commit, reveal } => {
                vec![
                    self.sign_complete_transaction(
                        commit,
                        reveal,
                        TransactionKind::BatchProofMethodId,
                    )
                    .await?,
                ]
            }
            DaTxs::Chunked {
                commit_chunks,
                reveal_chunks,
                commit,
                reveal,
            } => {
                self.sign_chunked_transaction(commit_chunks, reveal_chunks, commit, reveal)
                    .await?
            }
        };

        Ok(queued_txs)
    }

    async fn sign_complete_transaction(
        &self,
        commit: Transaction,
        reveal: TxWithId,
        kind: TransactionKind,
    ) -> Result<SignedTxPair> {
        trace!("Signing complete transaction");

        let signed_raw_commit_tx = self
            .client
            .sign_raw_transaction_with_wallet(&commit, None, None)
            .await?;

        if let Some(errors) = signed_raw_commit_tx.errors {
            return Err(BitcoinServiceError::InvalidTransaction(format!(
                "Failed to sign commit transaction: {:?}",
                errors
            )));
        }

        let serialized_reveal_tx = encode::serialize(&reveal.tx);
        Ok(SignedTxPair {
            commit: HexWithId {
                hex: signed_raw_commit_tx.hex,
                id: commit.compute_txid(),
            },
            reveal: HexWithId {
                hex: serialized_reveal_tx,
                id: reveal.id,
            },
            kind,
        })
    }

    async fn sign_chunked_transaction(
        &self,
        commit_chunks: Vec<Transaction>,
        reveal_chunks: Vec<Transaction>,
        commit: Transaction,
        reveal: TxWithId,
    ) -> Result<Vec<SignedTxPair>> {
        assert!(!commit_chunks.is_empty(), "Received empty chunks");
        assert_eq!(
            commit_chunks.len(),
            reveal_chunks.len(),
            "Chunks commit and reveal length mismatch"
        );

        trace!("Signing chunked transaction");

        let all_tx_map = commit_chunks
            .iter()
            .chain(reveal_chunks.iter())
            .chain([&commit, &reveal.tx].into_iter())
            .map(|tx| (tx.compute_txid(), tx.clone()))
            .collect::<HashMap<_, _>>();

        let mut raw_txs = Vec::with_capacity(all_tx_map.len());

        for (commit, reveal) in commit_chunks.into_iter().zip(reveal_chunks) {
            let mut inputs = vec![];

            for input in commit.input.iter() {
                if let Some(entry) = all_tx_map.get(&input.previous_output.txid) {
                    inputs.push(SignRawTransactionInput {
                        txid: input.previous_output.txid,
                        vout: input.previous_output.vout,
                        script_pub_key: entry.output[input.previous_output.vout as usize]
                            .script_pubkey
                            .clone(),
                        redeem_script: None,
                        amount: Some(entry.output[input.previous_output.vout as usize].value),
                    });
                }
            }

            let signed_raw_commit_tx = self
                .client
                .sign_raw_transaction_with_wallet(&commit, Some(inputs.as_slice()), None)
                .await?;

            if let Some(errors) = signed_raw_commit_tx.errors {
                return Err(BitcoinServiceError::InvalidTransaction(format!(
                    "Failed to sign commit transaction: {:?}",
                    errors
                )));
            }

            let serialized_reveal_tx = encode::serialize(&reveal);
            raw_txs.push(SignedTxPair {
                commit: HexWithId {
                    hex: signed_raw_commit_tx.hex,
                    id: commit.compute_txid(),
                },
                reveal: HexWithId {
                    hex: serialized_reveal_tx,
                    id: reveal.compute_txid(),
                },
                kind: TransactionKind::Chunks,
            });
        }

        let mut inputs = vec![];

        for input in commit.input.iter() {
            if let Some(entry) = all_tx_map.get(&input.previous_output.txid) {
                inputs.push(SignRawTransactionInput {
                    txid: input.previous_output.txid,
                    vout: input.previous_output.vout,
                    script_pub_key: entry.output[input.previous_output.vout as usize]
                        .script_pubkey
                        .clone(),
                    redeem_script: None,
                    amount: Some(entry.output[input.previous_output.vout as usize].value),
                });
            }
        }
        let signed_raw_commit_tx = self
            .client
            .sign_raw_transaction_with_wallet(&commit, Some(inputs.as_slice()), None)
            .await?;

        if let Some(errors) = signed_raw_commit_tx.errors {
            return Err(BitcoinServiceError::InvalidTransaction(format!(
                "Failed to sign the aggregate commit transaction: {:?}",
                errors
            )));
        }

        let serialized_reveal_tx = encode::serialize(&reveal.tx);

        raw_txs.push(SignedTxPair {
            commit: HexWithId {
                hex: signed_raw_commit_tx.hex,
                id: commit.compute_txid(),
            },
            reveal: HexWithId {
                hex: serialized_reveal_tx,
                id: reveal.id,
            },
            kind: TransactionKind::Aggregate,
        });

        Ok(raw_txs)
    }
}
