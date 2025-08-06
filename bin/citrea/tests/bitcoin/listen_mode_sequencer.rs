use std::collections::HashMap;
use std::net::SocketAddr;

use alloy_primitives::ruint::aliases::{U256, U32};
use alloy_primitives::{Address, U64};
use alloy_rpc_types::BlockId;
use async_trait::async_trait;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::TestCaseConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::NodeKind;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::{NodeT, Restart};
use citrea_e2e::Result;
use sov_ledger_rpc::LedgerRpcClient;
use tokio::time::sleep;

use super::get_citrea_path;
use crate::common::make_test_client;

struct ReadOnlySequencerTest;

/*
// TODO: Send some transcations before and after revival of the sequencer and compare the merkle roots etc.
// TODO: Add rollback (parts 19-20)
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
            // with_citrea_cli: true,
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
        let mut full_node_config = full_node.config.clone();
        sequencer.stop().await?;
        full_node.stop().await?;

        sleep(std::time::Duration::from_secs(2)).await;

        let mut read_only_node_config = readonly_sequencer.config.clone();

        read_only_node_config.node.listen_mode_config = None;
        // Restart with main sequencer config to make it the main sequencer
        readonly_sequencer
            .restart(Some(read_only_node_config), None)
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

        let new_sequencer_client_host = readonly_sequencer.config.rollup.rpc.bind_host.clone();
        let new_sequencer_client_port = readonly_sequencer.config.rollup.rpc.bind_port;

        let sequencer_rpc_url = format!(
            "http://{}:{}",
            new_sequencer_client_host, new_sequencer_client_port
        );

        if let Some(rc) = full_node_config.rollup.runner.as_mut() {
            rc.sequencer_client_url = sequencer_rpc_url.clone();
        }

        // Start full node with the new sequencer client url
        full_node.start(Some(full_node_config), None).await?;

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
