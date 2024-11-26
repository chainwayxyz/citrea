mod test_utils;

use std::collections::HashMap;
use std::str::FromStr;

use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use bitcoin_da::service::get_relevant_blobs_from_txs;
use bitcoin_da::spec::RollupParams;
use bitcoin_da::verifier::BitcoinVerifier;
use citrea_common::tasks::manager::TaskManager;
use citrea_e2e::config::TestCaseConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use sov_rollup_interface::da::{DaNamespace, DaVerifier};
use sov_rollup_interface::services::da::DaService;
use test_utils::{
    generate_mock_txs, get_citrea_path, get_default_service, get_mock_false_signature_txs_block,
    DEFAULT_DA_PRIVATE_KEY,
};

struct BitcoinServiceTest;

#[async_trait]
impl TestCase for BitcoinServiceTest {
    fn test_config() -> TestCaseConfig {
        // Only run bitcoin regtest
        TestCaseConfig {
            with_sequencer: false,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let mut task_manager = TaskManager::default();
        let da_node = f.bitcoin_nodes.get(0).unwrap();

        let service = get_default_service(&mut task_manager, &da_node.config).await;
        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
            to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
        });

        let (block, block_commitments, block_proofs) =
            generate_mock_txs(&service, da_node, &mut task_manager).await;
        let block_wtxids = block
            .txdata
            .iter()
            .map(|tx| tx.compute_wtxid().as_raw_hash().to_byte_array())
            .collect::<Vec<_>>();

        let pubkey;

        // Extracts relevant batch proof blobs with proof correctly
        {
            let (txs, inclusion_proof, completeness_proof) =
                service.extract_relevant_blobs_with_proof(&block, DaNamespace::ToBatchProver);
            assert_eq!(inclusion_proof.wtxids.len(), 29);
            assert_eq!(inclusion_proof.wtxids[1..], block_wtxids[1..]);
            // 3 valid commitments, and 1 invalid commitment with wrong public key
            assert_eq!(txs.len(), 4);
            // it is >= due to the probability that one of commit transactions ended up
            // with the prefix by chance (reveals are guaranteed to have a certain prefix)
            assert!(
                completeness_proof.len() >= 4,
                "expected completeness proof to have at least 4 txs, it has {}",
                completeness_proof.len()
            );

            // Since only one of the transactions has a malformed sender, we have to find the
            // tx that is not malformed, and get its public key
            pubkey = if txs[0].sender == txs[1].sender || txs[0].sender == txs[2].sender {
                txs[0].sender.0.clone()
            } else {
                txs[1].sender.0.clone()
            };

            // Ensure that the produced outputs are verifiable by the verifier
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    &txs,
                    inclusion_proof,
                    completeness_proof,
                    DaNamespace::ToBatchProver
                ),
                Ok(())
            );
        }

        // Extracts relevant light client proof blobs with proof correctly
        {
            let (txs, inclusion_proof, completeness_proof) =
                service.extract_relevant_blobs_with_proof(&block, DaNamespace::ToLightClientProver);
            assert_eq!(inclusion_proof.wtxids.len(), 29);
            assert_eq!(inclusion_proof.wtxids[1..], block_wtxids[1..]);
            // 2 complete and 2 aggregate proofs
            assert_eq!(txs.len(), 4);
            // it is >= due to the probability that one of commit transactions ended up
            // with the prefix by chance (reveals are guaranteed to have a certain prefix)
            assert!(
                completeness_proof.len() >= 4,
                "expected completeness proof to have at least 4 txs, it has {}",
                completeness_proof.len()
            );

            // Ensure that the produced outputs are verifiable by the verifier
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    &txs,
                    inclusion_proof,
                    completeness_proof,
                    DaNamespace::ToLightClientProver
                ),
                Ok(())
            );
        }

        // Extract relevant sequencer commitments
        {
            let commitments = service
                .extract_relevant_sequencer_commitments(&block, &pubkey)
                .unwrap();
            assert_eq!(commitments, block_commitments);
        }

        // Extract relevant zk proofs
        {
            let proofs = service
                .extract_relevant_zk_proofs(&block, &pubkey)
                .await
                .unwrap();
            assert_eq!(proofs, block_proofs);
        }

        // Batch proof tx blob signed with different private key should still be
        // returned as blob with sender recovered correctly.
        {
            let secp = Secp256k1::new();
            let wrong_secret = SecretKey::from_str(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33261",
            )
            .unwrap();
            let wrong_pubkey = wrong_secret
                .keypair(&secp)
                .public_key()
                .serialize()
                .to_vec();

            let false_sig_block = get_mock_false_signature_txs_block();

            let (txs, _, _) = service
                .extract_relevant_blobs_with_proof(&false_sig_block, DaNamespace::ToBatchProver);
            // There is one tx with right prefix, but wrong signature
            assert_eq!(txs.len(), 1);
            assert_eq!(txs[0].sender.0, wrong_pubkey);
        }

        {
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let secret = SecretKey::from_str(DEFAULT_DA_PRIVATE_KEY).unwrap();
            let da_pubkey = secret.keypair(&secp).public_key().serialize().to_vec();

            let wrong_secret = SecretKey::from_str(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33263",
            )
            .unwrap();
            let wrong_pubkey = wrong_secret
                .keypair(&secp)
                .public_key()
                .serialize()
                .to_vec();

            let txs = get_relevant_blobs_from_txs(
                block.txdata.iter().map(|tx| tx.inner().clone()).collect(),
                TO_BATCH_PROOF_PREFIX,
            );
            assert_eq!(txs.len(), 4);

            // Count the number of transactions occurring per public key
            let tx_count_of_pubkey = txs.into_iter().fold(HashMap::new(), |mut acc, tx| {
                *acc.entry(tx.sender.0).or_insert(0) += 1;
                acc
            });
            // 3 valid sequencer commitments
            assert_eq!(tx_count_of_pubkey.get(&da_pubkey).unwrap(), &3);
            // 1 invalid sequencer commitment due to different key
            assert_eq!(tx_count_of_pubkey.get(&wrong_pubkey).unwrap(), &1);
        }

        task_manager.abort().await;
        Ok(())
    }
}

#[cfg(feature = "native")]
#[tokio::test]
async fn test_bitcoin_service() -> Result<()> {
    TestCaseRunner::new(BitcoinServiceTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
