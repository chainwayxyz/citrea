use std::{collections::HashMap, net::SocketAddr, time::Duration};

use alloy_primitives::{
    ruint::aliases::{U256, U32},
    Address, U64,
};
use alloy_rpc_types::BlockId;
use async_trait::async_trait;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::{
    bitcoin::DEFAULT_FINALITY_DEPTH,
    client::Client,
    config::TestCaseConfig,
    framework::TestFramework,
    node::NodeKind,
    test_case::{TestCase, TestCaseRunner},
    traits::{NodeT, Restart},
    Result,
};
use sov_ledger_rpc::LedgerRpcClient;
use tokio::time::sleep;

use super::get_citrea_path;
use crate::common::make_test_client;

struct ReadOnlySequencerTest;

/*
1. Start a sequencer cluster with 2 sequencers
2. Configure one sequencer as a read-only sequencer
3. Send some L2 blocks to the sequencer with some transactions
4. Verify that the read-only sequencer can fetch the L2 blocks from the main sequencer
5. Send a commitment from the main sequencer
6. Verify that the read-only sequencer can fetch the commitment after the commitment is finalized but not before
7. Open a full node and sync to the main sequencer and see commitments
8. Publish more L2 blocks and verify that the read-only sequencer can fetch them
9. Send another commitment from the main sequencer
10. Verify that the read-only sequencer cannot fetch it because it is not finalized yet
11. Shut Down main sequencer and full node.
12. Revive read-only sequencer as main sequencer
13. Verify that after revival the read only sequencer does have the non-finalized commitment
14. Publish more l2 blocks from the revived sequencer with transactions
15. Restart full node with the new sequencer client url using revived sequencers url
16. See that full node can sync properly
17. Check the readonly sequencer historical state works as intended
18. Send commitment from revived sequencer and get it finalized
19. Verify that full node can fetch the finalized commitment and verify it
20. Roll back the revived sequencer and full node to a previous state
21. Publish more l2 blocks and still see full node can sync with revived sequencer
*/
#[async_trait]
impl TestCase for ReadOnlySequencerTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            n_nodes: HashMap::from([(NodeKind::Sequencer, 2)]),
            with_sequencer: true,
            with_full_node: true,
            with_citrea_cli: true,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(147)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let Some(cluster) = &mut f.sequencer_cluster else {
            anyhow::bail!("Sequencer cluster not running. Set n_nodes with Sequencer to 2 or more")
        };

        let mut cluster_iter = cluster.iter_mut();
        let sequencer = cluster_iter.next().unwrap();
        let readonly_sequencer = cluster_iter.next().unwrap();

        let full_node = f.full_node.as_mut().unwrap();

        let da = f.bitcoin_nodes.get_mut(0).unwrap();

        let sequ_host = sequencer.config.clone().rollup.rpc.bind_host;
        let sequ_port = sequencer.config.clone().rollup.rpc.bind_port;

        let seq_test_client =
            make_test_client(SocketAddr::new(sequ_host.parse()?, sequ_port)).await?;

        let max_l2_blocks_per_commitment = sequencer.config.node.max_l2_blocks_per_commitment;

        let some_address = Address::random();

        for _ in 0..max_l2_blocks_per_commitment / 2 {
            let _ = seq_test_client
                .send_eth(some_address, None, None, None, 1e18 as u128)
                .await
                .unwrap();
            sequencer.client.send_publish_batch_request().await?;
        }
        let head_l2_height = sequencer
            .client
            .http_client()
            .get_head_l2_block_height()
            .await?;

        // Wait for the readonly sequencer to catch up
        readonly_sequencer
            .wait_for_l2_height(head_l2_height.to::<u64>(), None)
            .await?;

        // Fetch all l2 blocks and compare them
        let l2_blocks = readonly_sequencer
            .client
            .http_client()
            .get_l2_block_range(U64::from(1), head_l2_height)
            .await
            .unwrap();

        let sequencer_rpc_blocks = sequencer
            .client
            .http_client()
            .get_l2_block_range(U64::from(1), head_l2_height)
            .await
            .unwrap();

        for (sequ_block, readonly_block) in sequencer_rpc_blocks.iter().zip(l2_blocks) {
            assert_eq!(*sequ_block, readonly_block);
            for (sequ_tx, readonly_tx) in readonly_block
                .as_ref()
                .unwrap()
                .txs
                .iter()
                .zip(readonly_block.as_ref().unwrap().txs.iter())
            {
                assert_eq!(sequ_tx, readonly_tx);
            }
        }

        for _ in 0..max_l2_blocks_per_commitment / 2 {
            sequencer.client.send_publish_batch_request().await?;
        }

        // Expect sequencer to send commitment
        da.wait_mempool_len(2, None).await?;
        da.generate(1).await?;

        let sequencers_commitment = sequencer
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(1))
            .await?;
        assert!(sequencers_commitment.is_some());
        let readonly_commitment = readonly_sequencer
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(1))
            .await?;
        assert!(readonly_commitment.is_none());

        // Now that it is finalized, readonly sequencer should be able to fetch it
        da.generate(DEFAULT_FINALITY_DEPTH - 1).await?;

        let finalized_height = da.get_finalized_height(None).await?;

        // Wait for the readonly sequencer l1 syncer to catch up
        readonly_sequencer
            .wait_for_l1_height(finalized_height, None)
            .await?;

        let readonly_commitment = readonly_sequencer
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(1))
            .await?;
        // Now should have the commitment
        assert!(readonly_commitment.is_some());

        full_node.wait_for_l1_height(finalized_height, None).await?;
        let full_node_commitment = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(1))
            .await?;
        // Full node should also have the commitment
        assert!(full_node_commitment.is_some());

        // Now publish more l2 blocks for another commitment
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        let head_l2_height = sequencer
            .client
            .http_client()
            .get_head_l2_block_height()
            .await?;

        readonly_sequencer
            .wait_for_l2_height(head_l2_height.to::<u64>(), None)
            .await?;

        full_node
            .wait_for_l2_height(head_l2_height.to::<u64>(), None)
            .await?;

        // Expect sequencer to send commitment
        da.wait_mempool_len(2, None).await?;

        // While the commitment is still in mempool,shutdown sequencer and fullnode,
        // **revive readonly sequencer as main sequencer**
        let main_sequencer_config = sequencer.config.clone();
        // Small hack until https://github.com/chainwayxyz/citrea-e2e/issues/124 is fixed
        readonly_sequencer.client = Client::new(
            &main_sequencer_config.rollup.rpc.bind_host,
            main_sequencer_config.rollup.rpc.bind_port,
        )
        .unwrap();
        sequencer.wait_until_stopped().await?;
        full_node.wait_until_stopped().await?;

        sleep(std::time::Duration::from_secs(2)).await;

        // Restart with main sequencer config to make it the main sequencer
        readonly_sequencer
            .restart(Some(main_sequencer_config), None)
            .await?;

        sleep(std::time::Duration::from_secs(2)).await;

        let readonly_sequencer_test_client = make_test_client(SocketAddr::new(
            readonly_sequencer.config.rollup.rpc.bind_host.parse()?,
            readonly_sequencer.config.rollup.rpc.bind_port,
        ))
        .await?;
        // Now the readonly sequencer is the main sequencer
        // Publish some blocks from the revived sequencer
        for _ in 0..max_l2_blocks_per_commitment / 2 {
            let _ = readonly_sequencer_test_client
                .send_eth(some_address, None, None, None, 1e18 as u128)
                .await
                .unwrap();
            readonly_sequencer
                .client
                .send_publish_batch_request()
                .await?;
        }

        // Start full node with the new sequencer client url
        full_node.start(None, None).await?;

        let head_l2_height = readonly_sequencer
            .client
            .http_client()
            .get_head_l2_block_height()
            .await?;

        // Wait for full node to sync with the new sequencer
        full_node
            .wait_for_l2_height(head_l2_height.to::<u64>(), None)
            .await?;

        // Check the balance of the address
        let balance = readonly_sequencer_test_client
            .eth_get_balance(some_address, None)
            .await
            .unwrap();
        assert!(balance == U256::from(max_l2_blocks_per_commitment as u128 * 1e18 as u128));

        // Check the balance of the address from the readonly sequencer
        let readonly_balance = readonly_sequencer_test_client
            .eth_get_balance(some_address, None)
            .await
            .unwrap();
        assert!(
            readonly_balance == U256::from(max_l2_blocks_per_commitment as u128 * 1e18 as u128)
        );

        // Check the historical balance of the address before it was revived
        let historical_balance = readonly_sequencer_test_client
            .eth_get_balance(some_address, Some(BlockId::earliest()))
            .await
            .unwrap();
        assert!(historical_balance == U256::from(0));
        let historical_balance = readonly_sequencer_test_client
            .eth_get_balance(some_address, Some(BlockId::number(1)))
            .await
            .unwrap();
        assert!(historical_balance == U256::from(1e18 as u128));
        let historical_balance = readonly_sequencer_test_client
            .eth_get_balance(some_address, Some(BlockId::number(2)))
            .await
            .unwrap();
        assert!(historical_balance == U256::from(2e18 as u128));

        // Also see that the revived sequencer can see the non-finalized commitment
        let revived_commitment = readonly_sequencer
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(2))
            .await?;
        assert!(revived_commitment.is_some());

        // Now finalize the commitment and also see that full node can fetch it as well
        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        full_node.wait_for_l1_height(finalized_height, None).await?;

        let full_node_commitment = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(2))
            .await?;
        assert!(full_node_commitment.is_some());

        // Now publish more l2 blocks and see that revived sequencer can send commitments
        for _ in 0..max_l2_blocks_per_commitment {
            readonly_sequencer
                .client
                .send_publish_batch_request()
                .await?;
        }

        // Expect sequencer to send commitment
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        let new_commitment = readonly_sequencer
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(3))
            .await?;
        assert!(new_commitment.is_some());

        // Wait for full node to sync with the new commitment
        full_node
            .wait_for_l1_height(finalized_height + DEFAULT_FINALITY_DEPTH, None)
            .await?;

        let new_full_node_commitment = full_node
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(3))
            .await?;
        assert!(new_full_node_commitment.is_some());

        assert_eq!(
            new_commitment.unwrap().merkle_root,
            new_full_node_commitment.unwrap().merkle_root
        );

        // Stop the readonly sequencer and full node
        readonly_sequencer.wait_until_stopped().await?;
        full_node.wait_until_stopped().await?;

        // Rollback bitcoin to initial height and drop existing txs so that we can re-send them out of order
        let initial_height_hash = da.get_block_hash(f.initial_da_height + 1).await?;
        da.invalidate_block(&initial_height_hash).await?;

        let citrea_cli = f.citrea_cli.as_ref().unwrap();
        // Rollback the revived sequencer, full node and da to a previous state
        citrea_cli
            .run(
                "rollback",
                &[
                    "--node-type",
                    "sequencer",
                    "--db-path",
                    readonly_sequencer
                        .config
                        .rollup
                        .storage
                        .path
                        .to_str()
                        .unwrap(),
                    "--l2-target",
                    "1",
                    "--l1-target",
                    &"120".to_string(),
                    "--sequencer-commitment-index",
                    "0",
                ],
            )
            .await?;

        citrea_cli
            .run(
                "rollback",
                &[
                    "--node-type",
                    "full-node",
                    "--db-path",
                    full_node.config.rollup.storage.path.to_str().unwrap(),
                    "--l2-target",
                    "1",
                    "--l1-target",
                    &"120".to_string(),
                    "--sequencer-commitment-index",
                    "0",
                ],
            )
            .await?;

        // Restart the readonly sequencer and full node
        readonly_sequencer.start(None, None).await?;
        sleep(std::time::Duration::from_secs(2)).await;
        full_node.start(None, None).await?;
        sleep(std::time::Duration::from_secs(2)).await;

        // Check the head l2 heights are the same
        let readonly_head_l2_height = readonly_sequencer
            .client
            .http_client()
            .get_head_l2_block_height()
            .await?;
        let full_node_head_l2_height = full_node
            .client
            .http_client()
            .get_head_l2_block_height()
            .await?;
        assert_eq!(readonly_head_l2_height, full_node_head_l2_height);

        // Publish more l2 blocks and see that full node can still sync with revived sequencer
        for _ in 0..max_l2_blocks_per_commitment {
            readonly_sequencer
                .client
                .send_publish_batch_request()
                .await?;
        }

        // Expect sequencer to send commitment
        da.wait_mempool_len(2, None).await?;
        da.generate(DEFAULT_FINALITY_DEPTH).await?;

        // Check that full node can fetch the new commitment
        let new_commitment = readonly_sequencer
            .client
            .http_client()
            .get_sequencer_commitment_by_index(U32::from(1))
            .await?;

        assert!(new_commitment.is_some());

        Ok(())
    }
}

#[tokio::test]
async fn read_only_sequencer_test() -> Result<()> {
    TestCaseRunner::new(ReadOnlySequencerTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// Test listen mode sequencer with sync_blocks_count = 0 (subscription only)
struct SubscriptionOnlyTest;

#[async_trait]
impl TestCase for SubscriptionOnlyTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            n_nodes: HashMap::from([(NodeKind::Sequencer, 2)]),
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let cluster = f.sequencer_cluster.as_mut().unwrap();
        let mut cluster_iter = cluster.iter_mut();
        let main_sequencer = cluster_iter.next().unwrap();
        let listen_mode_sequencer = cluster_iter.next().unwrap();

        // Configure listen mode with sync_blocks_count = 0, desactivates polling
        let mut listen_mode_config = listen_mode_sequencer.config.clone();
        listen_mode_config
            .node
            .listen_mode_config
            .as_mut()
            .unwrap()
            .sync_blocks_count = 0;

        listen_mode_sequencer
            .restart(Some(listen_mode_config), None)
            .await?;

        sleep(Duration::from_millis(1000)).await;

        for i in 1..50 {
            main_sequencer.client.send_publish_batch_request().await?;
            listen_mode_sequencer.wait_for_l2_height(i, None).await?;
        }

        let main_final_height = main_sequencer
            .client
            .ledger_get_head_l2_block_height()
            .await?;
        let listen_final_height = listen_mode_sequencer
            .client
            .ledger_get_head_l2_block_height()
            .await?;

        assert_eq!(main_final_height, listen_final_height);

        Ok(())
    }
}

#[tokio::test]
async fn test_subscription_only_mode() -> Result<()> {
    TestCaseRunner::new(SubscriptionOnlyTest).run().await
}

/// Test buffer behavior with gaps in subscriptions
struct OutOfOrderSubscriptionTest;

#[async_trait]
impl TestCase for OutOfOrderSubscriptionTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            n_nodes: HashMap::from([(NodeKind::Sequencer, 2)]),
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let cluster = f.sequencer_cluster.as_mut().unwrap();
        let mut cluster_iter = cluster.iter_mut();
        let main_sequencer = cluster_iter.next().unwrap();
        let listen_mode_sequencer = cluster_iter.next().unwrap();

        let max_l2_blocks_per_commitment = main_sequencer.config.node.max_l2_blocks_per_commitment;
        let subscription_lookahead_limit = 100;

        // Stop listen mode sequencer
        listen_mode_sequencer.wait_until_stopped().await?;

        // Generate blocks on main sequencer while listen mode is stopped, should act as gap in buffer
        for _ in 0..max_l2_blocks_per_commitment {
            main_sequencer.client.send_publish_batch_request().await?;
        }

        // Configure listen mode with sync_blocks_count = 0, desactivates polling
        let mut subscription_only_config = listen_mode_sequencer.config.clone();
        subscription_only_config
            .node
            .listen_mode_config
            .as_mut()
            .unwrap()
            .sync_blocks_count = 0;

        listen_mode_sequencer
            .start(Some(subscription_only_config), None)
            .await?;

        // Generate blocks that should be buffer by listen mode sequencer
        for _ in 0..max_l2_blocks_per_commitment {
            main_sequencer.client.send_publish_batch_request().await?;
        }

        // Stop listen mode sequencer again
        listen_mode_sequencer.wait_until_stopped().await?;

        // Generate blocks on main sequencer while listen mode is stopped, should act as gap in buffer
        for _ in 0..max_l2_blocks_per_commitment {
            main_sequencer.client.send_publish_batch_request().await?;
        }

        listen_mode_sequencer.start(None, None).await?;

        let main_height = main_sequencer
            .client
            .ledger_get_head_l2_block_height()
            .await?;
        let listen_mode_height = listen_mode_sequencer
            .client
            .ledger_get_head_l2_block_height()
            .await?;

        assert_eq!(main_height, max_l2_blocks_per_commitment * 3);
        assert_eq!(listen_mode_height, 0);

        // Generate above SUBSCRIPTION_LOOKAHEAD_LIMIT value of 100 so that subscription at tip are over the limit and not buffered
        for _ in 0..subscription_lookahead_limit {
            main_sequencer.client.send_publish_batch_request().await?;
        }

        let main_height = main_sequencer
            .client
            .ledger_get_head_l2_block_height()
            .await?;
        let listen_mode_height = listen_mode_sequencer
            .client
            .ledger_get_head_l2_block_height()
            .await?;

        assert_eq!(
            main_height,
            max_l2_blocks_per_commitment * 3 + subscription_lookahead_limit
        );
        assert_eq!(listen_mode_height, 0);

        let mut with_polling_config = listen_mode_sequencer.config.clone();
        with_polling_config
            .node
            .listen_mode_config
            .as_mut()
            .unwrap()
            .sync_blocks_count = 10;

        listen_mode_sequencer
            .restart(Some(with_polling_config), None)
            .await?;

        listen_mode_sequencer
            .wait_for_l2_height(main_height, None)
            .await?;
        let listen_mode_height = listen_mode_sequencer
            .client
            .ledger_get_head_l2_block_height()
            .await?;
        // Make sure listen mode catches up to tip with polling fallback
        assert_eq!(listen_mode_height, main_height);

        Ok(())
    }
}

#[tokio::test]
async fn test_out_of_order_subscription() -> Result<()> {
    TestCaseRunner::new(OutOfOrderSubscriptionTest).run().await
}
