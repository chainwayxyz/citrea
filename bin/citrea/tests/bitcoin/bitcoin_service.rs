use std::collections::HashMap;
use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;
use bitcoin_da::spec::RollupParams;
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_e2e::config::{BitcoinConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_primitives::REVEAL_TX_PREFIX;
use reth_tasks::TaskManager;
use sov_rollup_interface::da::{BlobReaderTrait, DaVerifier};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::Network;

use crate::bitcoin::utils::{generate_mock_txs, get_default_service, SEQUENCER_DA_PRIVATE_KEY};
use crate::bitcoin::{get_citrea_path, get_relevant_seqcoms_from_txs};

struct BitcoinServiceTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for BitcoinServiceTest {
    fn test_config() -> TestCaseConfig {
        // Only run bitcoin regtest
        TestCaseConfig::default()
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-limitancestorcount=50", "-limitdescendantcount=50"],
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let task_executor = self.task_manager.executor();

        let da_node = f.bitcoin_nodes.get(0).unwrap();
        let rollup_config = &f.ctx.config.sequencer[0].rollup;

        let service = get_default_service(&task_executor, &da_node.config, rollup_config).await;
        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_tx_prefix: REVEAL_TX_PREFIX.to_vec(),
            network: Network::Nightly,
        });

        let (block, block_commitments, block_proofs, _) =
            generate_mock_txs(&service, da_node, &task_executor, rollup_config).await;
        let block_wtxids = block
            .txdata
            .iter()
            .map(|tx| tx.compute_wtxid().as_raw_hash().to_byte_array())
            .collect::<Vec<_>>();

        let pubkey;

        // Extracts relevant sequencer commitments, batch proofs and method id update txs with proof correctly
        {
            let (mut txs, inclusion_proof, completeness_proof) =
                service.extract_relevant_blobs_with_proof(&block);
            assert_eq!(inclusion_proof.wtxids.len(), block_wtxids.len());
            assert_eq!(inclusion_proof.wtxids[1..], block_wtxids[1..]);
            // Tx-sender writes one commit/reveal pair per DA request in this setup:
            // 4 batch proofs, 3 sequencer commitments, and 2 method id updates.
            assert_eq!(txs.len(), 9);
            // it is >= due to the probability that one of commit transactions ended up
            // with the prefix by chance (reveals are guaranteed to have a certain prefix)
            assert!(
                completeness_proof.len() >= 9,
                "expected completeness proof to have at least 9 txs, it has {}",
                completeness_proof.len()
            );

            txs.iter_mut().for_each(|t| {
                t.full_data();
            });

            pubkey = txs[0].sender();

            // Ensure that the produced outputs are verifiable by the verifier
            assert_eq!(
                verifier.verify_transactions(&block.header, inclusion_proof, completeness_proof,),
                Ok(txs)
            );
        }

        // Extract relevant sequencer commitments
        {
            let mut commitments: Vec<_> = service
                .extract_relevant_sequencer_commitments(&block, pubkey.as_ref())
                .into_iter()
                .map(|(_, commitment)| commitment)
                .collect();
            commitments.sort_by_key(|commitment| commitment.index);
            let mut block_commitments = block_commitments.clone();
            block_commitments.sort_by_key(|commitment| commitment.index);
            assert_eq!(commitments, block_commitments);
        }

        // Extract relevant zk proofs
        {
            let mut proofs: Vec<_> = service
                .extract_relevant_zk_proofs(&block, pubkey.as_ref())
                .await
                .into_iter()
                .map(|(_, proof)| proof)
                .collect();
            proofs.sort();
            let mut block_proofs = block_proofs.clone();
            block_proofs.sort();
            assert_eq!(proofs, block_proofs);
        }

        {
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let secret = SecretKey::from_str(SEQUENCER_DA_PRIVATE_KEY).unwrap();
            let da_pubkey = secret.keypair(&secp).public_key().serialize().to_vec();

            let txs = get_relevant_seqcoms_from_txs(
                block.txdata.iter().map(|tx| tx.deref().clone()).collect(),
                REVEAL_TX_PREFIX,
            );
            assert_eq!(txs.len(), 3);

            // Count the number of transactions occurring per public key
            let tx_count_of_pubkey = txs.into_iter().fold(HashMap::new(), |mut acc, tx| {
                *acc.entry(tx.sender().0).or_insert(0) += 1;
                acc
            });
            // 3 valid sequencer commitments
            assert_eq!(tx_count_of_pubkey.get(&da_pubkey).unwrap(), &3);
        }

        Ok(())
    }
}

#[tokio::test]
async fn test_bitcoin_service() -> Result<()> {
    TestCaseRunner::new(BitcoinServiceTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}
