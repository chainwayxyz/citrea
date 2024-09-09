use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use async_trait::async_trait;
use bitcoin::secp256k1::generate_keypair;
use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig, FINALITY_DEPTH};
use bitcoin_da::spec::RollupParams;
use bitcoincore_rpc::RpcApi;
use citrea_primitives::{REVEAL_BATCH_PROOF_PREFIX, REVEAL_LIGHT_CLIENT_PREFIX};
use hex::ToHex;
use sov_rollup_interface::da::{DaData, SequencerCommitment};

use crate::bitcoin_e2e::config::{SequencerConfig, TestCaseConfig};
use crate::bitcoin_e2e::framework::TestFramework;
use crate::bitcoin_e2e::node::NodeKind;
use crate::bitcoin_e2e::test_case::{TestCase, TestCaseRunner};
use crate::bitcoin_e2e::Result;

/// This is a basic prover test showcasing spawning a bitcoin node as DA, a sequencer and a prover.
/// It generates soft confirmations and wait until it reaches the first commitment.
/// It asserts that the blob inscribe txs have been sent.
/// This catches regression to the default prover flow, such as the one introduced by [#942](https://github.com/chainwayxyz/citrea/pull/942) and [#973](https://github.com/chainwayxyz/citrea/pull/973)
struct BasicProverTest;

#[async_trait]
impl TestCase for BasicProverTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 10,
            test_mode: true,
            ..Default::default()
        }
    }

    async fn run_test(&self, f: &TestFramework) -> Result<()> {
        let Some(sequencer) = &f.sequencer else {
            bail!("Sequencer not running. Set TestCaseConfig with_sequencer to true")
        };

        let Some(prover) = &f.prover else {
            bail!("Prover not running. Set TestCaseConfig with_prover to true")
        };

        let Some(full_node) = &f.full_node else {
            bail!("FullNode not running. Set TestCaseConfig with_full_node to true")
        };

        let Some(da) = f.bitcoin_nodes.get(0) else {
            bail!("bitcoind not running. Test cannot run with bitcoind running as DA")
        };

        // Generate confirmed UTXOs
        da.generate(120, None).await?;

        let seq_height0 = sequencer.client.eth_block_number().await;
        assert_eq!(seq_height0, 0);

        let min_soft_confirmations_per_commitment =
            sequencer.min_soft_confirmations_per_commitment();

        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await;
        }

        da.generate(FINALITY_DEPTH, None).await?;

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(1, None).await?;

        da.generate(FINALITY_DEPTH, None).await?;
        let finalized_height = da.get_finalized_height().await?;
        prover.wait_for_l1_height(finalized_height, None).await;

        da.generate(FINALITY_DEPTH, None).await?;
        let proofs = full_node
            .wait_for_zkproofs(
                finalized_height + FINALITY_DEPTH,
                Some(Duration::from_secs(120)),
            )
            .await
            .unwrap();

        {
            // print some debug info about state diff
            let state_diff = &proofs[0].state_transition.state_diff;
            let state_diff_size: usize = state_diff
                .iter()
                .map(|(k, v)| k.len() + v.as_ref().map(|v| v.len()).unwrap_or_default())
                .sum();
            let borshed_state_diff = borsh::to_vec(state_diff).unwrap();
            let compressed_state_diff =
                bitcoin_da::helpers::compression::compress_blob(&borshed_state_diff);
            println!(
                "StateDiff: size {}, compressed {}",
                state_diff_size,
                compressed_state_diff.len()
            );
        }

        Ok(())
    }
}

struct SkipPreprovenCommitmentsTest;

#[async_trait]
impl TestCase for SkipPreprovenCommitmentsTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_prover: true,
            with_full_node: true,
            docker: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 10,
            test_mode: true,
            ..Default::default()
        }
    }

    async fn run_test(&self, f: &TestFramework) -> Result<()> {
        let Some(sequencer) = &f.sequencer else {
            bail!("Sequencer not running. Set TestCaseConfig with_sequencer to true")
        };

        let Some(prover) = &f.prover else {
            bail!("Prover not running. Set TestCaseConfig with_prover to true")
        };

        let Some(full_node) = &f.full_node else {
            bail!("FullNode not running. Set TestCaseConfig with_full_node to true")
        };

        let Some(da) = f.bitcoin_nodes.get(0) else {
            bail!("bitcoind not running. Test cannot run with bitcoind running as DA")
        };

        let _initial_height = f.initial_da_height;

        let (secret_key, _public_key) = generate_keypair(&mut rand::thread_rng());
        let secret_key = secret_key.secret_bytes().encode_hex();
        // let key_pair = Keypair::from_secret_key(&secp, &secret_key);
        // let mut buf = [0u8; constants::SECRET_KEY_SIZE * 2];
        // to_hex(&self.secret_bytes(), &mut buf).expect("fixed-size hex serialization");
        let da_config = &f.bitcoin_nodes.get(0).unwrap().config;
        let bitcoin_da_service_config = BitcoinServiceConfig {
            node_url: format!(
                "http://127.0.0.1:{}/wallet/{}",
                da_config.rpc_port,
                NodeKind::Bitcoin
            ),
            node_username: da_config.rpc_user.clone(),
            node_password: da_config.rpc_password.clone(),
            network: bitcoin::Network::Regtest,
            da_private_key: Some(secret_key),
        };
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let bitcoin_da_service = Arc::new(
            BitcoinService::new_with_wallet_check(
                bitcoin_da_service_config,
                RollupParams {
                    reveal_light_client_prefix: REVEAL_LIGHT_CLIENT_PREFIX.to_vec(),
                    reveal_batch_prover_prefix: REVEAL_BATCH_PROOF_PREFIX.to_vec(),
                },
                tx,
            )
            .await
            .unwrap(),
        );
        bitcoin_da_service.clone().spawn_da_queue(rx);

        // Generate 1 FINALIZED DA block.
        da.generate(1 + FINALITY_DEPTH, None).await?;

        let seq_height0 = sequencer.client.eth_block_number().await;
        assert_eq!(seq_height0, 0);

        for _ in 0..10 {
            sequencer.client.send_publish_batch_request().await;
        }

        da.generate(1 + FINALITY_DEPTH, None).await?;

        // Wait for blob inscribe tx to be in mempool
        da.wait_mempool_len(1, None).await?;

        da.generate(1 + FINALITY_DEPTH, None).await?;

        let finalized_height = da.get_finalized_height().await?;
        println!("FINALIZED HEIGHT: {}", finalized_height);
        prover
            .wait_for_l1_height(finalized_height, Some(Duration::from_secs(300)))
            .await;

        da.generate(5, None).await?;
        let proofs = full_node
            .wait_for_zkproofs(finalized_height + 5, Some(Duration::from_secs(120)))
            .await
            .unwrap();

        assert!(proofs
            .first()
            .unwrap()
            .state_transition
            .preproven_commitments
            .is_empty());

        // Fetch the commitment created from the previous L1 range
        let commitments: Vec<SequencerCommitment> = sequencer
            .client
            .ledger_get_sequencer_commitments_on_slot_by_number(finalized_height)
            .await
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|response| SequencerCommitment {
                merkle_root: response.merkle_root,
                l2_start_block_number: response.l2_start_block_number,
                l2_end_block_number: response.l2_end_block_number,
            })
            .collect();

        let fee_sat_per_vbyte = bitcoin_da_service.get_fee_rate().await.unwrap();
        bitcoin_da_service
            .send_transaction_with_fee_rate(
                None,
                DaData::SequencerCommitment(commitments.first().unwrap().clone()),
                fee_sat_per_vbyte,
            )
            .await
            .unwrap();

        da.generate(5, None).await?;

        prover
            .wait_for_l1_height(FINALITY_DEPTH, Some(Duration::from_secs(300)))
            .await;

        assert_eq!(
            proofs
                .first()
                .unwrap()
                .state_transition
                .preproven_commitments
                .len(),
            1
        );

        Ok(())
    }
}

#[tokio::test]
async fn basic_prover_test() -> Result<()> {
    TestCaseRunner::new(BasicProverTest).run().await
}

#[ignore]
#[tokio::test]
async fn prover_skips_preproven_commitments_test() -> Result<()> {
    TestCaseRunner::new(SkipPreprovenCommitmentsTest)
        .run()
        .await
}
