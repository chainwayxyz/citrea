use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin_da::service::FINALITY_DEPTH;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::config::{
    BatchProverConfig, LightClientProverConfig, SequencerConfig, TestCaseConfig,
};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::Config;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::NodeT;
use citrea_e2e::Result;
use citrea_light_client_prover::rpc::LightClientProverRpcClient;
use reth_primitives::Address;
use sov_ledger_rpc::client::RpcClient;

use super::batch_prover_test::wait_for_zkproofs;
use super::get_citrea_path;
use crate::evm::make_test_client;

const TEN_MINS: Duration = Duration::from_secs(10 * 60);

struct LightClientProvingTest;

#[async_trait]
impl TestCase for LightClientProvingTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 5,
            da_update_interval_ms: 500,
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            enable_recovery: false,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        // publish min_soft_confirmations_per_commitment confirmations
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(min_soft_confirmations_per_commitment, None)
            .await?;

        // Wait for commitment tx to be submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await.unwrap();

        // Finalize the DA block which contains the commitment tx
        da.generate(FINALITY_DEPTH, None).await.unwrap();

        let commitment_l1_height = da.get_finalized_height().await.unwrap();

        // Wait for batch prover to generate proof for commitment
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Assert that commitment is queryable
        let commitments = batch_prover
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(commitment_l1_height)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments.len(), 1);

        // Ensure that batch proof is submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await.unwrap();

        // Finalize the DA block which contains the batch proof tx
        da.generate(FINALITY_DEPTH, None).await.unwrap();

        let batch_proof_l1_height = da.get_finalized_height().await.unwrap();

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;
        assert!(lcp.is_some());

        let finalized_height = da.get_finalized_height().await?;
        // Wait for full node to see zkproofs
        let batch_proof =
            wait_for_zkproofs(full_node, finalized_height, Some(Duration::from_secs(7200)))
                .await
                .unwrap();

        let light_client_proof = lcp.unwrap();
        assert_eq!(
            light_client_proof
                .light_client_proof_output
                .state_root
                .to_vec(),
            batch_proof[0].proof_output.final_state_root
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_proving() -> Result<()> {
    TestCaseRunner::new(LightClientProvingTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct LightClientProvingTestMultipleProofs;

#[async_trait]
impl TestCase for LightClientProvingTestMultipleProofs {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        let mut cfg = SequencerConfig {
            min_soft_confirmations_per_commitment: 20,
            da_update_interval_ms: 500,
            ..Default::default()
        };

        cfg.mempool_conf.max_account_slots = 400;
        cfg
    }

    fn batch_prover_config() -> BatchProverConfig {
        BatchProverConfig {
            enable_recovery: false,
            ..Default::default()
        }
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            enable_recovery: false,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        let rpc_bind_host = sequencer.config().rpc_bind_host();
        let rpc_bind_port = sequencer.config().rpc_bind_port();

        let socket_addr = SocketAddr::new(rpc_bind_host.parse().unwrap(), rpc_bind_port);

        let seq_test_client = make_test_client(socket_addr).await.unwrap();

        let n_commitments = 4;

        // publish min_soft_confirmations_per_commitment confirmations
        for _ in 0..n_commitments * min_soft_confirmations_per_commitment {
            // sequencer.client.http_client().eth_send_raw_transaction(data)
            for _ in 0..30 {
                let address = Address::random();
                let _pending = seq_test_client
                    .send_eth(address, None, None, None, 1u128)
                    .await
                    .unwrap();
            }
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(n_commitments * min_soft_confirmations_per_commitment, None)
            .await?;

        // Wait for commitment txs to be submitted to DA
        da.wait_mempool_len((n_commitments * 2) as usize, Some(TEN_MINS))
            .await
            .unwrap();

        // Finalize the DA block which contains the commitment txs
        da.generate(FINALITY_DEPTH, None).await.unwrap();

        let commitment_l1_height = da.get_finalized_height().await.unwrap();

        // Wait for batch prover to generate proofs for commitments
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(Duration::from_secs(1200)))
            .await
            .unwrap();

        // Assert that commitments are queryable
        let commitments = batch_prover
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(commitment_l1_height)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments.len(), n_commitments as usize);

        // Ensure that batch proofs is submitted to DA (2x reveal & 2x commit txs)
        da.wait_mempool_len(4, Some(TEN_MINS)).await.unwrap();

        // Finalize the DA block which contains the batch proof tx
        da.generate(FINALITY_DEPTH, None).await?;
        let batch_proof_l1_height = da.get_finalized_height().await?;
        // Wait for the full node to see all process verify and store all batch proofs
        full_node
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;
        let batch_proofs = wait_for_zkproofs(
            full_node,
            batch_proof_l1_height,
            Some(Duration::from_secs(30)),
        )
        .await
        .unwrap();
        assert_eq!(batch_proofs.len(), 2);

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;
        assert!(lcp.is_some());

        let light_client_proof = lcp.unwrap();
        assert_eq!(
            light_client_proof
                .light_client_proof_output
                .state_root
                .to_vec(),
            batch_proofs[1].proof_output.final_state_root
        );

        assert!(light_client_proof
            .light_client_proof_output
            .unchained_batch_proofs_info
            .is_empty());

        // Generate another da block so we generate another lcp
        da.generate(1, None).await?;

        let last_finalized_height = da.get_finalized_height().await?;

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(last_finalized_height, Some(TEN_MINS))
            .await?;

        // Expect light client prover to have generated light client proof
        let lcp2 = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(last_finalized_height)
            .await?;
        assert!(lcp2.is_some());

        // Since there are no batch proofs the state root should be the same as the last one
        let light_client_proof2 = lcp2.unwrap();
        assert_eq!(
            light_client_proof2
                .light_client_proof_output
                .state_root
                .to_vec(),
            batch_proofs[1].proof_output.final_state_root
        );
        assert_eq!(
            light_client_proof2.light_client_proof_output.state_root,
            light_client_proof.light_client_proof_output.state_root
        );

        // The last processed l2 height should also be the same because there are no new batch proofs
        assert_eq!(
            light_client_proof2.light_client_proof_output.last_l2_height,
            light_client_proof.light_client_proof_output.last_l2_height
        );

        // Should always be the same
        assert_eq!(
            light_client_proof2
                .light_client_proof_output
                .l2_genesis_state_root,
            light_client_proof
                .light_client_proof_output
                .l2_genesis_state_root
        );

        assert!(light_client_proof2
            .light_client_proof_output
            .unchained_batch_proofs_info
            .is_empty());

        // Let's generate a new batch proof
        // publish min_soft_confirmations_per_commitment confirmations
        let l2_height = sequencer
            .client
            .ledger_get_head_soft_confirmation_height()
            .await?;
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        sequencer
            .wait_for_l2_height(l2_height + min_soft_confirmations_per_commitment, None)
            .await?;

        // Wait for commitment tx to be submitted to DA
        da.wait_mempool_len(2, Some(TEN_MINS)).await.unwrap();

        // Finalize the DA block which contains the commitment txs
        da.generate(FINALITY_DEPTH, None).await.unwrap();

        let commitment_l1_height = da.get_finalized_height().await.unwrap();

        // Wait for batch prover to generate proofs for commitments
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Assert that commitments are queryable
        let commitments = batch_prover
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(commitment_l1_height)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(commitments.len(), 1);

        // Ensure that batch proofs is submitted to DA (1x reveal & 1x commit txs)
        da.wait_mempool_len(2, Some(TEN_MINS)).await.unwrap();

        // Finalize the DA block which contains the batch proof tx
        da.generate(FINALITY_DEPTH, None).await?;
        let batch_proof_l1_height = da.get_finalized_height().await?;
        // Wait for the full node to see all process verify and store all batch proofs
        full_node
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await?;
        let batch_proofs = wait_for_zkproofs(
            full_node,
            batch_proof_l1_height,
            Some(Duration::from_secs(30)),
        )
        .await
        .unwrap();
        assert_eq!(batch_proofs.len(), 1);

        // Wait for light client prover to process batch proofs.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(TEN_MINS))
            .await
            .unwrap();

        // Expect light client prover to have generated light client proof
        let lcp3 = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(batch_proof_l1_height)
            .await?;
        assert!(lcp3.is_some());

        let light_client_proof3 = lcp3.unwrap();
        assert_eq!(
            light_client_proof3
                .light_client_proof_output
                .state_root
                .to_vec(),
            batch_proofs[0].proof_output.final_state_root
        );

        assert_eq!(
            light_client_proof3
                .light_client_proof_output
                .l2_genesis_state_root,
            light_client_proof
                .light_client_proof_output
                .l2_genesis_state_root
        );

        assert_ne!(
            light_client_proof3.light_client_proof_output.last_l2_height,
            light_client_proof.light_client_proof_output.last_l2_height
        );

        assert_ne!(
            light_client_proof3.light_client_proof_output.state_root,
            light_client_proof.light_client_proof_output.state_root
        );

        assert!(light_client_proof3
            .light_client_proof_output
            .unchained_batch_proofs_info
            .is_empty());

        Ok(())
    }
}

#[tokio::test]
async fn test_light_client_proving_multiple_proofs() -> Result<()> {
    TestCaseRunner::new(LightClientProvingTestMultipleProofs)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
