use std::net::SocketAddr;
use std::str::FromStr;

use alloy_primitives::Address;
use async_trait::async_trait;
use citrea_e2e::config::{CitreaMode, SequencerConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use ethereum_rpc::LayerStatus;
use reth_primitives::BlockNumberOrTag;

use crate::common::make_test_client;

use super::get_citrea_path;

struct DelayedSyncTest;

#[async_trait]
impl TestCase for DelayedSyncTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        let seq_test_client = make_test_client(SocketAddr::new(
            sequencer.config.rpc_bind_host().parse()?,
            sequencer.config.rpc_bind_port(),
        ))
        .await?;

        let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

        for _ in 0..10 {
            let _ = seq_test_client
                .send_eth(addr, None, None, None, 0u128)
                .await?;
            sequencer.client.send_publish_batch_request().await?;
        }

        sequencer.wait_for_l2_height(10, None).await?;
        full_node.wait_for_l2_height(10, None).await?;

        // Compare block 10 between sequencer and full node
        let seq_block = seq_test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Number(10)))
            .await;

        let full_node_test_client = make_test_client(SocketAddr::new(
            full_node.config.rpc_bind_host().parse()?,
            full_node.config.rpc_bind_port(),
        ))
        .await?;

        let full_node_block = full_node_test_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Number(10)))
            .await;

        assert_eq!(
            seq_block.header.state_root,
            full_node_block.header.state_root
        );
        assert_eq!(seq_block.header.hash, full_node_block.header.hash);

        Ok(())
    }
}

#[tokio::test]
async fn test_delayed_sync() -> Result<()> {
    TestCaseRunner::new(DelayedSyncTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct SyncStatusTest;

#[async_trait]
impl TestCase for SyncStatusTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            with_full_node: true,
            mode: CitreaMode::DevAllForks,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            min_soft_confirmations_per_commitment: 1000,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).unwrap();

        let seq_test_client = make_test_client(SocketAddr::new(
            sequencer.config.rpc_bind_host().parse()?,
            sequencer.config.rpc_bind_port(),
        ))
        .await?;

        let full_node_test_client = make_test_client(SocketAddr::new(
            full_node.config.rpc_bind_host().parse()?,
            full_node.config.rpc_bind_port(),
        ))
        .await?;

        let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

        for _ in 0..300 {
            let _ = seq_test_client
                .send_eth(addr, None, None, None, 0u128)
                .await?;
            sequencer.client.send_publish_batch_request().await?;
        }

        sequencer.wait_for_l2_height(300, None).await?;
        full_node.wait_for_l2_height(5, None).await?;

        // Check sync status while syncing
        let l2_status = full_node_test_client.citrea_sync_status().await.l2_status;
        match l2_status {
            LayerStatus::Syncing(syncing) => {
                assert!(
                    syncing.synced_block_number.to::<u64>() > 0
                        && syncing.synced_block_number.to::<u64>() < 300
                );
                assert_eq!(syncing.head_block_number.to::<u64>(), 300);
            }
            _ => panic!("Expected syncing status"),
        }

        full_node.wait_for_l2_height(300, None).await?;

        // Check sync status after fully synced
        let l2_status = full_node_test_client.citrea_sync_status().await.l2_status;
        match l2_status {
            LayerStatus::Synced(synced_up_to) => {
                assert_eq!(synced_up_to.to::<u64>(), 300);
            }
            _ => panic!("Expected synced status"),
        }

        // Generate DA blocks and check L1 sync status
        for _ in 0..19 {
            da.generate(1).await?;
        }

        full_node.wait_for_l1_height(1, None).await?;

        // Check L1 sync status while syncing
        let l1_status = full_node_test_client.citrea_sync_status().await.l1_status;
        match l1_status {
            LayerStatus::Syncing(syncing) => {
                assert!(
                    syncing.synced_block_number.to::<u64>() > 0
                        && syncing.synced_block_number.to::<u64>() < 20
                );
                assert_eq!(syncing.head_block_number.to::<u64>(), 20);
            }
            _ => panic!("Expected syncing status"),
        }

        // Wait for L1 sync to complete
        full_node.wait_for_l1_height(20, None).await?;

        // Check L1 sync status after fully synced
        let l1_status = full_node_test_client.citrea_sync_status().await.l1_status;
        match l1_status {
            LayerStatus::Synced(synced_up_to) => {
                assert_eq!(synced_up_to.to::<u64>(), 20);
            }
            _ => panic!("Expected synced status"),
        }

        Ok(())
    }
}

#[tokio::test]
async fn test_sync_status() -> Result<()> {
    TestCaseRunner::new(SyncStatusTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
