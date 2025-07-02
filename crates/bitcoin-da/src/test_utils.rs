use anyhow::Context;
use bitcoin::hashes::Hash;
use sov_rollup_interface::da::{DaTxRequest, DataOnDa};

use crate::error::BitcoinServiceError;
use crate::helpers::builders::body_builders::{DaTxs, RawTxData};
use crate::helpers::builders::test_utils::{
    test_create_single_aggregate, test_create_single_chunk,
};
use crate::service::{split_proof, BitcoinService, Result};

impl BitcoinService {
    pub async fn test_send_separate_chunk_transaction_with_fee_rate(
        &self,
        tx_request: DaTxRequest,
        fee_sat_per_vbyte: u64,
    ) -> Result<()> {
        let network = self.network;

        let da_private_key = self.da_private_key.expect("No private key set");

        match tx_request {
            DaTxRequest::ZKProof(zkproof) => {
                let mut txids = vec![];
                let data = split_proof(zkproof)?;

                let reveal_light_client_prefix = self.reveal_tx_prefix.clone();
                // create inscribe transactions
                let mut reveal_chunks = vec![];
                match data {
                    RawTxData::Chunks(chunks) => {
                        for body in chunks {
                            // get all available utxos that are not already spent
                            let utxos = self.get_utxos().await?;
                            let utxos = utxos
                                .into_iter()
                                .filter(|utxo| {
                                    utxo.amount == 50 * 10_u64.pow(8)
                                        && utxo.spendable
                                        && utxo.solvable
                                })
                                .collect::<Vec<_>>();

                            let prev_utxo = self.get_prev_utxo().await;

                            // get address from a utxo
                            let address = utxos[0]
                                .address
                                .clone()
                                .context("Missing address")?
                                .require_network(network)?;

                            let da_txs = test_create_single_chunk(
                                body,
                                &da_private_key,
                                prev_utxo,
                                utxos,
                                address,
                                fee_sat_per_vbyte,
                                fee_sat_per_vbyte,
                                network,
                                &reveal_light_client_prefix,
                            )?;

                            let (txid, wtxid) =
                                if let DaTxs::Complete { ref reveal, .. } = da_txs {
                                    Some((
                                        reveal.id.to_byte_array(),
                                        reveal.tx.compute_wtxid().to_byte_array(),
                                    ))
                                } else {
                                    None
                                }
                                .unwrap();

                            let signed_txs = self.tx_signer.sign_da_txs(da_txs).await?;

                            reveal_chunks.push((txid, wtxid));

                            // Send chunks as if they were complete txs separate from each other
                            txids.extend(self.send_signed_transaction(&signed_txs[0]).await?);
                        }
                        // Now send the aggregate data
                        let (reveal_tx_ids, reveal_wtx_ids): (Vec<_>, Vec<_>) =
                            reveal_chunks.iter().map(|tx| (tx.0, tx.1)).collect();
                        let aggregate = DataOnDa::Aggregate(reveal_tx_ids, reveal_wtx_ids);
                        // To sign the list of tx ids we assume they form a contiguous list of bytes
                        let reveal_body: Vec<u8> =
                            borsh::to_vec(&aggregate).expect("Aggregate serialize must not fail");

                        // get all available utxos that are not already spent
                        let utxos = self.get_utxos().await?;
                        let utxos = utxos
                            .into_iter()
                            .filter(|utxo| utxo.amount >= 50 * 10_u64.pow(8))
                            .collect::<Vec<_>>();
                        let prev_utxo = self.get_prev_utxo().await;

                        // get address from a utxo
                        let address = utxos[0]
                            .address
                            .clone()
                            .context("Missing address")?
                            .require_network(network)?;

                        let da_txs = test_create_single_aggregate(
                            reveal_body,
                            &da_private_key,
                            utxos,
                            address,
                            network,
                            fee_sat_per_vbyte,
                            fee_sat_per_vbyte,
                            prev_utxo,
                            &self.reveal_tx_prefix,
                        )?;

                        let signed_txs = self.tx_signer.sign_da_txs(da_txs).await?;

                        txids.extend(self.send_signed_transaction(&signed_txs[0]).await?);
                    }
                    _ => {
                        return Err(BitcoinServiceError::InvalidTransaction(
                            "Expected chunks only for this function".to_string(),
                        ))
                    }
                }
            }
            _ => {
                return Err(BitcoinServiceError::InvalidTransaction(
                    "Expected chunk zk proof".to_owned(),
                ))
            }
        }

        Ok(())
    }
}
