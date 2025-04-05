use std::net::SocketAddr;
use std::str::FromStr;

use alloy_primitives::{Address, U64};
use alloy_rpc_types::BlockNumberOrTag;
use async_trait::async_trait;
use citrea_e2e::config::{CitreaMode, SequencerConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::NodeT;
use citrea_e2e::Result;
use ethereum_rpc::LayerStatus;
use sov_ledger_rpc::LedgerRpcClient;

use super::get_citrea_path;
use crate::common::make_test_client;

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
            mode: CitreaMode::Dev,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 1000,
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
                        && syncing.synced_block_number.to::<u64>() < 165
                );
                assert_eq!(syncing.head_block_number.to::<u64>(), 165);
            }
            _ => panic!("Expected syncing status"),
        }

        // Wait for L1 sync to complete
        full_node.wait_for_l1_height(165, None).await?;

        // Check L1 sync status after fully synced
        let l1_status = full_node_test_client.citrea_sync_status().await.l1_status;
        match l1_status {
            LayerStatus::Synced(synced_up_to) => {
                assert_eq!(synced_up_to.to::<u64>(), 165);
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

struct SameBlockSyncTest;

#[async_trait]
impl TestCase for SameBlockSyncTest {
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

        let full_node_test_client = make_test_client(SocketAddr::new(
            full_node.config.rpc_bind_host().parse()?,
            full_node.config.rpc_bind_port(),
        ))
        .await?;

        // Send test transactions and publish blocks
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
async fn test_same_block_sync() -> Result<()> {
    TestCaseRunner::new(SameBlockSyncTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct L2BlocksDifferentBlocksTest;

#[async_trait]
impl TestCase for L2BlocksDifferentBlocksTest {
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
        let da = f.bitcoin_nodes.get(0).unwrap();

        // First publish blocks fast to land in same DA block
        for _ in 0..6 {
            sequencer.client.send_publish_batch_request().await?;
        }

        sequencer.wait_for_l2_height(6, None).await?;
        full_node.wait_for_l2_height(6, None).await?;

        // Verify l2 blocks match
        for i in 1..=6 {
            let seq_l2_block = sequencer
                .client
                .http_client()
                .get_l2_block_by_number(U64::from(i))
                .await?
                .unwrap();
            let full_l2_block = full_node
                .client
                .http_client()
                .get_l2_block_by_number(U64::from(i))
                .await?
                .unwrap();

            assert_eq!(
                seq_l2_block.header.state_root,
                full_l2_block.header.state_root
            );
        }

        // Generate new DA block
        da.generate(1).await?;

        // Publish more blocks
        for _ in 0..6 {
            sequencer.client.send_publish_batch_request().await?;
        }

        sequencer.wait_for_l2_height(12, None).await?;
        full_node.wait_for_l2_height(12, None).await?;

        // Verify new l2 blocks match but are on different DA blocks
        for i in 7..=12 {
            let seq_l2_block = sequencer
                .client
                .http_client()
                .get_l2_block_by_number(U64::from(i))
                .await?
                .unwrap();
            let full_node_l2_block = full_node
                .client
                .http_client()
                .get_l2_block_by_number(U64::from(i))
                .await?
                .unwrap();
            let hash = full_node_l2_block.header.hash;
            let full_node_l2_block_by_hash = full_node
                .client
                .http_client()
                .get_l2_block_by_hash(hash.into())
                .await?
                .unwrap();

            assert_eq!(
                seq_l2_block.header.state_root,
                full_node_l2_block.header.state_root
            );
            assert_eq!(seq_l2_block, full_node_l2_block_by_hash);
        }

        Ok(())
    }
}

#[tokio::test]
async fn test_l2_blocks_different_blocks() -> Result<()> {
    TestCaseRunner::new(L2BlocksDifferentBlocksTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct HealthCheckTest;

#[async_trait]
impl TestCase for HealthCheckTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_full_node: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            test_mode: false,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let full_node = f.full_node.as_mut().unwrap();

        // Create test clients
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

        // Wait for initial blocks
        sequencer.wait_for_l2_height(2, None).await?;
        full_node.wait_for_l2_height(4, None).await?;

        // Check healthy status
        let status = full_node_test_client.healthcheck().await.unwrap();
        assert_eq!(status, 200);
        let status = seq_test_client.healthcheck().await.unwrap();
        assert_eq!(status, 200);

        // Stop sequencer and verify unhealthy status
        f.sequencer.as_mut().unwrap().stop().await?;

        let status = full_node_test_client.healthcheck().await.unwrap();
        assert_eq!(status, 500);

        Ok(())
    }
}

#[tokio::test]
async fn test_healthcheck() -> Result<()> {
    TestCaseRunner::new(HealthCheckTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
