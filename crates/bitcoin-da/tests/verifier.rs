mod test_utils;

use std::time::Duration;

use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoin::{ScriptBuf, Witness};
use bitcoin_da::helpers::merkle_tree::BitcoinMerkleTree;
use bitcoin_da::spec::proof::InclusionMultiProof;
use bitcoin_da::spec::RollupParams;
use bitcoin_da::verifier::{BitcoinVerifier, ValidationError, WITNESS_COMMITMENT_PREFIX};
use citrea_e2e::config::{BitcoinConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_primitives::REVEAL_TX_PREFIX;
use reth_tasks::TaskManager;
use sov_rollup_interface::da::{BlobReaderTrait, DaVerifier};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::Network;
use test_utils::macros::assert_panic;
use test_utils::{
    generate_mock_txs, get_citrea_path, get_default_service, get_mock_nonsegwit_block,
};

struct BitcoinVerifierTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for BitcoinVerifierTest {
    fn test_config() -> TestCaseConfig {
        // Only run bitcoin regtest
        TestCaseConfig {
            with_sequencer: false,
            ..Default::default()
        }
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

        let service = get_default_service(&task_executor, &da_node.config).await;
        let (block, _, _, _) = generate_mock_txs(&service, da_node, &task_executor).await;

        let (mut txs, inclusion_proof, completeness_proof) =
            service.extract_relevant_blobs_with_proof(&block);

        txs.iter_mut().for_each(|t| {
            t.full_data();
        });

        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_tx_prefix: REVEAL_TX_PREFIX.to_vec(),
            network: Network::Nightly,
        });

        // Can be verified
        {
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof.clone(),
                    completeness_proof.clone(),
                ),
                Ok(txs.clone()),
            );
        }

        // Test non-segwit block
        {
            let nonsegwit_block = get_mock_nonsegwit_block();
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
                verifier.verify_transactions(&nonsegwit_block.header, inclusion_proof, vec![],),
                Ok(Vec::new())
            );
        }

        // False coinbase input witness should fail
        {
            let mut block_txs = block.txdata.clone();

            // Malform witness
            block_txs[0].input[0].witness = Witness::from_slice(&[vec![1; 32]]);

            // Recreate inclusion proof
            let tree = BitcoinMerkleTree::new(
                block_txs
                    .iter()
                    .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                    .collect(),
            );
            let mut inclusion_proof = InclusionMultiProof {
                wtxids: block_txs
                    .iter()
                    .map(|t| t.compute_wtxid().to_byte_array())
                    .collect(),
                coinbase_tx: block_txs[0].clone(),
                coinbase_merkle_proof: tree.get_idx_path(0),
            };
            // Coinbase tx wtxid should be [0u8;32]
            inclusion_proof.wtxids[0] = [0; 32];

            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof,
                    completeness_proof.clone(),
                ),
                Err(ValidationError::IncorrectInclusionProof),
            );
        }

        // False coinbase script pubkey should fail
        {
            let mut block_txs = block.txdata.clone();

            let idx = block_txs[0]
                .output
                .iter()
                .position(|output| {
                    output
                        .script_pubkey
                        .to_bytes()
                        .starts_with(WITNESS_COMMITMENT_PREFIX)
                })
                .unwrap();
            // Malform coinbase script pubkey
            let mut bytes = block_txs[0].output[idx].script_pubkey.to_bytes();
            bytes[6] = bytes[6].wrapping_add(1);

            block_txs[0].output[idx].script_pubkey = ScriptBuf::from_bytes(bytes);

            // Recreate inclusion proof
            let tree = BitcoinMerkleTree::new(
                block_txs
                    .iter()
                    .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                    .collect(),
            );
            let mut inclusion_proof = InclusionMultiProof {
                wtxids: block_txs
                    .iter()
                    .map(|t| t.compute_wtxid().to_byte_array())
                    .collect(),
                coinbase_tx: block_txs[0].clone(),
                coinbase_merkle_proof: tree.get_idx_path(0),
            };
            // Coinbase tx wtxid should be [0u8;32]
            inclusion_proof.wtxids[0] = [0; 32];

            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof,
                    completeness_proof.clone(),
                ),
                Err(ValidationError::IncorrectInclusionProof),
            );
        }

        // False witness script should fail
        {
            let mut block_txs = block.txdata.clone();
            let mut completeness_proof = completeness_proof.clone();

            let relevant_tx = block_txs
                .iter_mut()
                .find(|tx| tx.compute_wtxid() == completeness_proof[0].compute_wtxid())
                .unwrap();

            // Malform the witness
            let mut malformed_witness = relevant_tx.input[0].witness.to_vec();
            malformed_witness[0][0] = malformed_witness[0][0].wrapping_add(1);

            completeness_proof[0].input[0].witness = Witness::from_slice(&malformed_witness);
            relevant_tx.input[0].witness = Witness::from_slice(&malformed_witness);
            assert_eq!(
                completeness_proof[0].compute_wtxid(),
                relevant_tx.compute_wtxid()
            );

            let tree = BitcoinMerkleTree::new(
                block_txs
                    .iter()
                    .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                    .collect(),
            );

            let inclusion_proof = InclusionMultiProof {
                wtxids: block_txs
                    .iter()
                    .map(|t| t.compute_wtxid().to_byte_array())
                    .collect(),
                coinbase_tx: block_txs[0].clone(),
                coinbase_merkle_proof: tree.get_idx_path(0),
            };

            assert_eq!(
                verifier.verify_transactions(&block.header, inclusion_proof, completeness_proof,),
                Err(ValidationError::RelevantTxNotInProof),
            );
        }

        // Different witness ids should fail
        {
            let mut ip = inclusion_proof.clone();

            // Prefix is made 2, which will look like inclusion proof
            // has extra relevant transaction in it.
            ip.wtxids[0] = [2; 32];
            assert_eq!(
                verifier.verify_transactions(&block.header, ip, completeness_proof.clone(),),
                Err(ValidationError::RelevantTxNotInProof),
            );

            let mut ip = inclusion_proof.clone();

            ip.wtxids[1] = [16; 32];
            assert_eq!(
                verifier.verify_transactions(&block.header, ip, completeness_proof.clone(),),
                Err(ValidationError::IncorrectInclusionProof),
            );
        }

        // Extra tx in inclusion
        {
            let mut inclusion_proof = inclusion_proof.clone();

            inclusion_proof.wtxids.push([5; 32]);
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof,
                    completeness_proof.clone(),
                ),
                Err(ValidationError::HeaderInclusionTxCountMismatch),
            );
        }

        // Missing tx in inclusion should fail
        {
            let mut inclusion_proof = inclusion_proof.clone();

            inclusion_proof.wtxids.pop();
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof,
                    completeness_proof.clone(),
                ),
                Err(ValidationError::HeaderInclusionTxCountMismatch),
            );
        }

        // Break order of inclusion should fail
        {
            let mut inclusion_proof = inclusion_proof.clone();

            inclusion_proof.wtxids.swap(0, 1);
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof,
                    completeness_proof.clone(),
                ),
                Err(ValidationError::IncorrectInclusionProof),
            );
        }

        // Missing tx in completeness proof should panic
        {
            let mut completeness_proof = completeness_proof.clone();

            completeness_proof.pop();
            assert_panic!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof.clone(),
                    completeness_proof,
                ),
                "itertools: .zip_eq() reached end of one iterator before the other"
            );
        }

        // Extra tx in completeness proof should panic
        {
            let mut completeness_proof = completeness_proof.clone();

            completeness_proof.push(block.txdata[0].clone());
            assert_panic!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof.clone(),
                    completeness_proof,
                ),
                "itertools: .zip_eq() reached end of one iterator before the other"
            );
        }

        // Nonrelevant tx in completeness proof should fail
        {
            let mut completeness_proof = completeness_proof.clone();

            let nonrelevant_tx = block
                .txdata
                .iter()
                .find(|tx| !completeness_proof.contains(tx))
                .unwrap()
                .clone();
            completeness_proof[0] = nonrelevant_tx;
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof.clone(),
                    completeness_proof,
                ),
                Err(ValidationError::RelevantTxNotInProof),
            );
        }

        // Break completeness proof order should fail
        {
            let mut completeness_proof = completeness_proof.clone();

            completeness_proof.swap(1, 2);
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof.clone(),
                    completeness_proof,
                ),
                Err(ValidationError::RelevantTxNotInProof),
            );
        }

        // Break tx order and completeness proof order should fail
        {
            let mut completeness_proof = completeness_proof.clone();
            let mut txs = txs.clone();

            completeness_proof.swap(0, 1);
            txs.swap(0, 1);
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof.clone(),
                    completeness_proof,
                ),
                Err(ValidationError::RelevantTxNotInProof),
            );
        }

        Ok(())
    }
}

#[cfg(feature = "native")]
#[tokio::test]
async fn test_bitcoin_verifier() -> Result<()> {
    TestCaseRunner::new(BitcoinVerifierTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}
