//! Real proofs on Succinct's prover network, ignored by default because every run spends PROVE.
//! Run them with `make test-succinct-network`, which needs NETWORK_PRIVATE_KEY. The nodes
//! inherit it from the test's environment.
use std::time::Duration;

use alloy_primitives::{U32, U64};
use async_trait::async_trait;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::{
    BatchProverConfig, CitreaMode, LightClientProverConfig, ProverGuestRunConfig, SequencerConfig,
    TestCaseConfig,
};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_light_client_prover::rpc::LightClientProverRpcClient;
use sov_ledger_rpc::LedgerRpcClient;

use crate::bitcoin::get_citrea_path;
use crate::bitcoin::utils::wait_for_zkproofs;

/// Network proofs take minutes, where mock proofs take seconds.
const NETWORK_PROVING_TIMEOUT: Duration = Duration::from_secs(3600);

/// Fails fast instead of waiting out the timeouts on proving jobs that cannot request proofs.
fn require_network_env() {
    assert!(
        std::env::var_os("NETWORK_PRIVATE_KEY").is_some(),
        "Set NETWORK_PRIVATE_KEY to prove on Succinct's prover network"
    );
}

/// Prove mode proves on the network.
fn proving_batch_prover() -> BatchProverConfig {
    BatchProverConfig {
        proving_mode: ProverGuestRunConfig::Prove,
        ..Default::default()
    }
}

/// One commitment proven on the network, then verified by a full node.
struct NetworkBatchProofTest;

#[async_trait]
impl TestCase for NetworkBatchProofTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        proving_batch_prover()
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        for _ in 0..sequencer.max_l2_blocks_per_commitment() {
            sequencer.client.send_publish_batch_request().await?;
        }
        // Wait for the commitment tx, then finalize it
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;
        batch_prover
            .wait_for_l1_height(finalized_height, Some(NETWORK_PROVING_TIMEOUT))
            .await?;

        // Wait for the batch proof tx, then finalize it
        da.wait_mempool_len(2, Some(NETWORK_PROVING_TIMEOUT))
            .await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;
        let proofs = wait_for_zkproofs(
            full_node,
            finalized_height,
            Some(NETWORK_PROVING_TIMEOUT),
            1,
        )
        .await
        .unwrap();

        // The proof ends at the sequencer's state root for the commitment's last L2 block.
        let output = &proofs[0].proof_output;
        let commitment_index = output.sequencer_commitment_index_range.0;
        let commitment = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(commitment_index.to::<u32>()))
            .await?
            .unwrap();
        let l2_block = sequencer
            .client
            .http_client()
            .get_l2_block_by_number(U64::from(commitment.l2_end_block_number))
            .await?
            .unwrap();
        assert_eq!(
            output.state_roots.last().unwrap().0,
            l2_block.header.state_root.to_vec()
        );
        Ok(())
    }
}

#[tokio::test]
#[ignore = "spends PROVE on Succinct's prover network; run with make test-succinct-network"]
async fn succinct_network_batch_proof() -> Result<()> {
    require_network_env();
    TestCaseRunner::new(NetworkBatchProofTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// Light client proofs on the network, one per L1 block, each verifying the previous one as an
/// assumption, until one covers a network batch proof.
struct NetworkLightClientProofTest;

#[async_trait]
impl TestCase for NetworkLightClientProofTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_batch_prover: true,
            with_light_client_prover: true,
            with_full_node: true,
            mode: CitreaMode::Dev,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 5,
            da_update_interval_ms: 500,
            ..Default::default()
        }
    }

    fn batch_prover_config() -> BatchProverConfig {
        proving_batch_prover()
    }

    fn light_client_prover_config() -> LightClientProverConfig {
        LightClientProverConfig {
            proving_mode: ProverGuestRunConfig::Prove,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(195)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let light_client_prover = f.light_client_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
        sequencer
            .wait_for_l2_height(max_l2_blocks_per_commitment, None)
            .await?;
        // Wait for the commitment tx, then finalize it
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let commitment_l1_height = da.get_finalized_height(None).await?;
        batch_prover
            .wait_for_l1_height(commitment_l1_height, Some(NETWORK_PROVING_TIMEOUT))
            .await?;

        // Wait for the batch proof tx, then finalize it
        da.wait_mempool_len(2, Some(NETWORK_PROVING_TIMEOUT))
            .await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        // Every L1 block up to here gets its own light client proof, one after another.
        light_client_prover
            .wait_for_l1_height(batch_proof_l1_height, Some(2 * NETWORK_PROVING_TIMEOUT))
            .await?;
        let light_client_proof = light_client_prover
            .client
            .http_client()
            .get_light_client_proof_by_l1_height(U64::from(batch_proof_l1_height))
            .await?
            .expect("The light client should have proven the batch proof's L1 block");

        let batch_proofs = wait_for_zkproofs(
            full_node,
            batch_proof_l1_height,
            Some(NETWORK_PROVING_TIMEOUT),
            1,
        )
        .await
        .unwrap();
        assert_eq!(
            light_client_proof
                .light_client_proof_output
                .l2_state_root
                .to_vec(),
            batch_proofs[0].proof_output.final_state_root()
        );
        Ok(())
    }
}

#[tokio::test]
#[ignore = "spends PROVE on Succinct's prover network; run with make test-succinct-network"]
async fn succinct_network_light_client_proofs() -> Result<()> {
    require_network_env();
    TestCaseRunner::new(NetworkLightClientProofTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
