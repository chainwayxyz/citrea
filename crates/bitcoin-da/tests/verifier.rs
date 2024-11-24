mod test_utils;

use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin_da::helpers::merkle_tree::BitcoinMerkleTree;
use bitcoin_da::helpers::parsers::{parse_light_client_transaction, ParsedLightClientTransaction};
use bitcoin_da::spec::blob::BlobWithSender;
use bitcoin_da::spec::proof::InclusionMultiProof;
use bitcoin_da::spec::RollupParams;
use bitcoin_da::verifier::{BitcoinVerifier, ValidationError};
use citrea_common::tasks::manager::TaskManager;
use citrea_e2e::config::TestCaseConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_primitives::{TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use sov_rollup_interface::da::{DaNamespace, DaVerifier};
use sov_rollup_interface::services::da::DaService;
use test_utils::macros::assert_panic;
use test_utils::{
    generate_mock_txs, generate_nonsegwit_block, get_citrea_path, get_default_service,
};

struct BitcoinVerifierTest;

#[async_trait]
impl TestCase for BitcoinVerifierTest {
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
        let (block, _, _) = generate_mock_txs(&service, da_node, &mut task_manager).await;

        let (b_txs, b_inclusion_proof, b_completeness_proof) =
            service.extract_relevant_blobs_with_proof(&block, DaNamespace::ToBatchProver);
        let (l_txs, l_inclusion_proof, l_completeness_proof) =
            service.extract_relevant_blobs_with_proof(&block, DaNamespace::ToLightClientProver);

        let verifier = BitcoinVerifier::new(RollupParams {
            to_batch_proof_prefix: TO_BATCH_PROOF_PREFIX.to_vec(),
            to_light_client_prefix: TO_LIGHT_CLIENT_PREFIX.to_vec(),
        });

        // Correct batch proof
        {
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof.clone(),
                    b_completeness_proof.clone(),
                    DaNamespace::ToBatchProver,
                ),
                Ok(()),
            );
        }

        // Correct light client proof
        {
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    &l_txs,
                    l_inclusion_proof.clone(),
                    l_completeness_proof.clone(),
                    DaNamespace::ToLightClientProver,
                ),
                Ok(()),
            );
        }

        // Inverted namespaces should fail
        {
            // batch transactions with light client namespace
            assert!(verifier
                .verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof.clone(),
                    b_completeness_proof.clone(),
                    DaNamespace::ToLightClientProver,
                )
                .is_err());

            // light client transactions with batch namespace
            assert!(verifier
                .verify_transactions(
                    &block.header,
                    &l_txs,
                    l_inclusion_proof.clone(),
                    l_completeness_proof.clone(),
                    DaNamespace::ToBatchProver,
                )
                .is_err());
        }

        // Test non-segwit block
        {
            let nonsegwit_block = generate_nonsegwit_block(da_node, &service).await;
            let txs = nonsegwit_block.txdata.as_slice();

            let tree = BitcoinMerkleTree::new(
                txs.iter()
                    .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                    .collect(),
            );

            let inclusion_proof = InclusionMultiProof {
                wtxids: txs
                    .iter()
                    .map(|t| t.compute_wtxid().to_raw_hash().to_byte_array())
                    .collect(),
                coinbase_tx: txs[0].clone(),
                coinbase_merkle_proof: tree.get_idx_path(0),
            };
            assert_eq!(
                verifier.verify_transactions(
                    &nonsegwit_block.header,
                    &[],
                    inclusion_proof,
                    vec![],
                    DaNamespace::ToBatchProver,
                ),
                Ok(())
            );
        }

        // False coinbase input witness should fail
        {
            // TODO: do
        }

        // False coinbase script pubkey should fail
        {
            // TODO: do
        }

        // False witness script should fail
        {
            // TODO: do
        }

        // Different witness ids should fail
        {
            let mut b_inclusion_proof = b_inclusion_proof.clone();

            b_inclusion_proof.wtxids[0] = [1; 32];
            assert!(verifier
                .verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof.clone(),
                    b_completeness_proof.clone(),
                    DaNamespace::ToBatchProver,
                )
                .is_err());

            b_inclusion_proof.wtxids[0] = [0; 32];
            b_inclusion_proof.wtxids[1] = [16; 32];
            assert!(verifier
                .verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof,
                    b_completeness_proof.clone(),
                    DaNamespace::ToBatchProver,
                )
                .is_err());
        }

        // Extra tx in inclusion
        {
            let mut b_inclusion_proof = b_inclusion_proof.clone();

            b_inclusion_proof.wtxids.push([5; 32]);
            assert!(verifier
                .verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof,
                    b_completeness_proof.clone(),
                    DaNamespace::ToBatchProver,
                )
                .is_err());
        }

        // Missing tx in inclusion should fail
        {
            let mut b_inclusion_proof = b_inclusion_proof.clone();

            b_inclusion_proof.wtxids.pop();
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof,
                    b_completeness_proof.clone(),
                    DaNamespace::ToBatchProver,
                ),
                Err(ValidationError::HeaderInclusionTxCountMismatch),
            );
        }

        // Break order of inclusion should fail
        {
            let mut b_inclusion_proof = b_inclusion_proof.clone();

            b_inclusion_proof.wtxids.swap(0, 1);
            assert!(verifier
                .verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof,
                    b_completeness_proof.clone(),
                    DaNamespace::ToBatchProver,
                )
                .is_err(),);
        }

        // Missing tx in completeness proof should panic
        {
            let mut b_completeness_proof = b_completeness_proof.clone();

            b_completeness_proof.pop();
            assert_panic!(
                verifier.verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof.clone(),
                    b_completeness_proof,
                    DaNamespace::ToBatchProver,
                ),
                "itertools: .zip_eq() reached end of one iterator before the other"
            );
        }

        // Extra tx in completeness proof should panic
        {
            let mut b_completeness_proof = b_completeness_proof.clone();

            b_completeness_proof.push(block.txdata[0].clone());
            assert_panic!(
                verifier.verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof.clone(),
                    b_completeness_proof,
                    DaNamespace::ToBatchProver,
                ),
                "itertools: .zip_eq() reached end of one iterator before the other"
            );
        }

        // Nonrelevant tx in completeness proof should fail
        {
            let mut b_completeness_proof = b_completeness_proof.clone();

            let nonrelevant_tx = block
                .txdata
                .iter()
                .find(|tx| !b_completeness_proof.contains(tx))
                .unwrap()
                .clone();
            b_completeness_proof[0] = nonrelevant_tx;
            assert!(verifier
                .verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof.clone(),
                    b_completeness_proof.clone(),
                    DaNamespace::ToBatchProver,
                )
                .is_err(),);
        }

        // Break completeness proof order should fail
        {
            let mut b_completeness_proof = b_completeness_proof.clone();

            b_completeness_proof.swap(1, 2);
            assert!(verifier
                .verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof.clone(),
                    b_completeness_proof,
                    DaNamespace::ToBatchProver,
                )
                .is_err(),);
        }

        // Break tx order should fail
        {
            let mut b_txs = b_txs.clone();

            b_txs.swap(0, 1);
            assert!(verifier
                .verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof.clone(),
                    b_completeness_proof.clone(),
                    DaNamespace::ToBatchProver,
                )
                .is_err(),);
        }

        // Break tx order and completeness proof order should fail
        {
            let mut b_completeness_proof = b_completeness_proof.clone();
            let mut b_txs = b_txs.clone();

            b_completeness_proof.swap(0, 1);
            b_txs.swap(0, 1);
            assert!(verifier
                .verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof.clone(),
                    b_completeness_proof,
                    DaNamespace::ToBatchProver,
                )
                .is_err(),);
        }

        // Missing tx should fail
        {
            let mut b_txs = b_txs.clone();

            b_txs.pop();
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof.clone(),
                    b_completeness_proof.clone(),
                    DaNamespace::ToBatchProver,
                ),
                Err(ValidationError::ValidBlobNotFoundInBlobs),
            );
        }

        // Tamper tx content of batch proof should fail
        {
            let mut b_txs = b_txs.clone();

            b_txs[0] = BlobWithSender::new(vec![2; 152], b_txs[0].sender.0.clone(), b_txs[0].hash);
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof.clone(),
                    b_completeness_proof.clone(),
                    DaNamespace::ToBatchProver,
                ),
                Err(ValidationError::BlobContentWasModified),
            );
        }

        // Tamper tx content of light client proof should fail
        {
            let mut l_txs = l_txs.clone();

            l_txs[0] = BlobWithSender::new(vec![2; 152], l_txs[0].sender.0.clone(), l_txs[0].hash);
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    &l_txs,
                    l_inclusion_proof.clone(),
                    l_completeness_proof.clone(),
                    DaNamespace::ToLightClientProver,
                ),
                Err(ValidationError::BlobContentWasModified),
            );
        }

        // Tamper tx sender of batch proof should fail
        {
            let mut b_txs = b_txs.clone();

            let mut blob = b_txs[0].blob.clone();
            blob.advance(blob.total_len());
            let blob = blob.accumulator().to_vec();

            b_txs[0] = BlobWithSender::new(blob, vec![2; 33], b_txs[0].hash);
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    &b_txs,
                    b_inclusion_proof,
                    b_completeness_proof,
                    DaNamespace::ToBatchProver,
                ),
                Err(ValidationError::IncorrectSenderInBlob),
            );
        }

        // Tamper tx sender of light client proof should fail
        {
            let mut l_txs = l_txs.clone();

            let mut blob = l_txs[0].blob.clone();
            blob.advance(blob.total_len());
            let blob = blob.accumulator().to_vec();

            l_txs[0] = BlobWithSender::new(blob, vec![2; 33], l_txs[0].hash);
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    &l_txs,
                    l_inclusion_proof.clone(),
                    l_completeness_proof.clone(),
                    DaNamespace::ToLightClientProver,
                ),
                Err(ValidationError::IncorrectSenderInBlob),
            );
        }

        // Non-decompressed light client proof blob should fail
        {
            let mut l_txs = l_txs.clone();

            let body = {
                let parsed = parse_light_client_transaction(&l_completeness_proof[0]).unwrap();
                match parsed {
                    ParsedLightClientTransaction::Complete(complete) => complete.body, // normally we should decompress the tx body
                    _ => panic!("Should not select zk proof tx other than complete"),
                }
            };

            l_txs[0] = BlobWithSender::new(body, l_txs[0].sender.0.clone(), l_txs[0].hash);
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    &l_txs,
                    l_inclusion_proof,
                    l_completeness_proof,
                    DaNamespace::ToLightClientProver,
                ),
                Err(ValidationError::BlobContentWasModified),
            );
        }

        task_manager.abort().await;
        Ok(())
    }
}

#[cfg(feature = "native")]
#[tokio::test]
async fn test_bitcoin_verifier() -> Result<()> {
    TestCaseRunner::new(BitcoinVerifierTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
