use std::net::SocketAddr;
use std::time::Duration;

use alloy_rpc_types::TransactionTrait;
use alloy_sol_types::{sol, SolCall};
use async_trait::async_trait;
use bitcoin::hashes::Hash;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::SequencerConfig;
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::Restart;
use citrea_e2e::Result;
use citrea_evm::system_contracts::BitcoinLightClient;
use citrea_evm::{BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS, SYSTEM_SIGNER};
use sov_ledger_rpc::LedgerRpcClient;
use tokio::time::sleep;

use super::get_citrea_path;
use crate::common::client::TestClient;
use crate::common::make_test_client;

sol! {
    function setBlockInfo(bytes32 blockHash, bytes32 witnessRoot, uint256 coinbaseDepth);
}

struct BasicSequencerTest;

#[async_trait]
impl TestCase for BasicSequencerTest {
    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let Some(sequencer) = &f.sequencer else {
            anyhow::bail!("Sequencer not running. Set TestCaseConfig with_sequencer to true")
        };

        sequencer.client.send_publish_batch_request().await?;
        sequencer.client.wait_for_l2_block(1, None).await?;

        let head_batch0 = sequencer
            .client
            .http_client()
            .get_head_l2_block()
            .await?
            .unwrap();
        assert_eq!(head_batch0.header.height.to::<u64>(), 1);

        sequencer.client.send_publish_batch_request().await?;
        sequencer.client.wait_for_l2_block(2, None).await?;

        let head_batch1 = sequencer
            .client
            .http_client()
            .get_head_l2_block()
            .await?
            .unwrap();
        assert_eq!(head_batch1.header.height.to::<u64>(), 2);

        Ok(())
    }
}

#[tokio::test]
async fn basic_sequencer_test() -> Result<()> {
    TestCaseRunner::new(BasicSequencerTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// This test checks the sequencer behavior when missed DA blocks are detected.
/// 1. Run the sequencer.
/// 2. Create a L2 blocks on top of an L1.
/// 3. Shutdown sequencer
/// 4. Create a bunch of L1 blocks.
/// 5. Start the sequencer.
///
/// Each DA block should have a L2 block created for it.
struct SequencerMissedDaBlocksTest;

#[async_trait]
impl TestCase for SequencerMissedDaBlocksTest {
    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 1000,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_mut().unwrap();
        let da = f.bitcoin_nodes.get(0).unwrap();

        let seq_test_client = make_test_client(SocketAddr::new(
            sequencer.config.rpc_bind_host().parse()?,
            sequencer.config.rpc_bind_port(),
        ))
        .await?;

        let init_da_height = da
            .get_finalized_height(Some(DEFAULT_FINALITY_DEPTH))
            .await?;

        // Create initial DA blocks
        da.generate(3).await?;

        sequencer.client.send_publish_batch_request().await?;

        sequencer.wait_until_stopped().await?;

        // Create 100 more DA blocks while the sequencer is down
        // This on its own should generate 10 l2 blocks
        da.generate(100).await?;

        // Restart the sequencer
        sequencer.start(None, None).await?;

        sequencer.client.send_publish_batch_request().await?;

        sequencer.client.wait_for_l2_block(13, None).await?;

        let head_l2_block_height = sequencer.client.ledger_get_head_l2_block_height().await?;

        for l1_height in init_da_height..init_da_height + 103 {
            let res: String = seq_test_client
                .contract_call(
                    BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
                    BitcoinLightClient::get_block_hash(l1_height).to_vec(),
                    None,
                )
                .await
                .unwrap();
            let l1_block_hash = da.get_block_hash(l1_height).await?;
            assert_eq!(
                l1_block_hash.to_raw_hash().to_byte_array().to_vec(),
                hex::decode(&res[2..]).unwrap()
            );
        }

        // check that the sequencer has at least one block for each 10 DA blocks
        // starting from l2 #2 all the way up to l2 #12 without no gaps
        // Blocks should have 10 txs which are all set block infos
        for i in 1..=head_l2_block_height {
            let block = seq_test_client
                .eth_get_block_by_number(Some(i.into()))
                .await;

            if i == 1 {
                assert_eq!(block.transactions.len(), 3);
            } else if i == 12 {
                assert_eq!(block.transactions.len(), 2);
            } else if i == 13 {
                assert_eq!(block.transactions.len(), 1);
            } else {
                assert_eq!(block.transactions.len(), 10);
            }
        }

        Ok(())
    }
}

#[tokio::test]
async fn test_sequencer_missed_da_blocks() -> Result<()> {
    TestCaseRunner::new(SequencerMissedDaBlocksTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct SequencerL1FeeParamsTest;

#[async_trait]
impl TestCase for SequencerL1FeeParamsTest {
    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_mut().unwrap();
        let one_sat_vb: u128 = 2_500_000_000; // 1 sat/vbyte to wei/byte

        sequencer.client.send_publish_batch_request().await?;
        sequencer.wait_for_l2_height(1, None).await?;

        let block = sequencer
            .client
            .http_client()
            .get_head_l2_block()
            .await?
            .unwrap();
        let initial_fee_rate: u128 = block.header.l1_fee_rate.to();
        assert_eq!(initial_fee_rate, one_sat_vb); // assert we start with 1 sat/vbyte
        sequencer.wait_until_stopped().await?;

        // Test changing l1 fee rate multiplier
        let mut new_config = sequencer.config.clone();
        new_config.node.l1_fee_rate_multiplier = 2.0;

        // Restart the sequencer with new config
        sequencer.start(Some(new_config), None).await?;
        sequencer.client.send_publish_batch_request().await?;
        sequencer.client.wait_for_l2_block(2, None).await?;
        // assert the fee rate has doubled
        let block = sequencer
            .client
            .http_client()
            .get_head_l2_block()
            .await?
            .unwrap();
        let updated_fee_rate: u128 = block.header.l1_fee_rate.to();
        assert_eq!(updated_fee_rate, 2 * one_sat_vb);
        sequencer.wait_until_stopped().await?;

        // Test changing max l1 fee rate
        let mut new_config = sequencer.config.clone();
        new_config.node.l1_fee_rate_multiplier = 2.0;
        new_config.node.max_l1_fee_rate_sat_vb = 1;

        // Restart the sequencer with new config
        sequencer.start(Some(new_config), None).await?;
        sequencer.client.send_publish_batch_request().await?;
        sequencer.client.wait_for_l2_block(3, None).await?;
        // assert the fee rate is capped at max l1 fee rate
        let block = sequencer
            .client
            .http_client()
            .get_head_l2_block()
            .await?
            .unwrap();
        let updated_fee_rate: u128 = block.header.l1_fee_rate.to();
        assert_eq!(updated_fee_rate, one_sat_vb);

        Ok(())
    }
}

#[tokio::test]
async fn test_sequencer_l1_fee_params() -> Result<()> {
    TestCaseRunner::new(SequencerL1FeeParamsTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// 1. Generate DA blocks and (re)start the sequencer so it deterministically
///    folds every finalized DA block into L2 blocks.
/// 2. Assert the RPC reports the finalized L1 height the sequencer caught up to,
///    cross-checked against the Bitcoin light client contract.
/// 3. Generate more DA blocks and assert the reported height advances (and that
///    it persisted across the restart).
struct SequencerLastScannedL1HeightTest;

#[async_trait]
impl TestCase for SequencerLastScannedL1HeightTest {
    fn sequencer_config() -> SequencerConfig {
        // Avoid commitment churn interfering with DA block accounting during the test.
        SequencerConfig {
            max_l2_blocks_per_commitment: 1000,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_mut().unwrap();
        let da = f.bitcoin_nodes.get(0).unwrap();

        let seq_test_client = make_test_client(SocketAddr::new(
            sequencer.config.rpc_bind_host().parse()?,
            sequencer.config.rpc_bind_port(),
        ))
        .await?;

        // Generate DA blocks, then restart the sequencer so that on startup it
        // deterministically folds every finalized DA block into L2 blocks (avoids
        // racing the DA block monitor's polling interval).
        da.generate(5).await?;
        let target_l1_height = da
            .get_finalized_height(Some(DEFAULT_FINALITY_DEPTH))
            .await?;

        sequencer.wait_until_stopped().await?;
        sequencer.start(None, None).await?;

        // A single publish processes all missed DA blocks up to the finalized height.
        sequencer.client.send_publish_batch_request().await?;
        // `wait_for_l1_height` polls `getLastScannedL1Height` (the RPC under test).
        sequencer.wait_for_l1_height(target_l1_height, None).await?;

        let scanned = sequencer.client.ledger_get_last_scanned_l1_height().await?;
        assert!(
            scanned > 0,
            "sequencer should report a non-zero last scanned L1 height"
        );
        assert_eq!(
            scanned, target_l1_height,
            "sequencer should have scanned up to the finalized L1 height"
        );

        // The reported height must be a real L1 block the sequencer referenced in
        // the Bitcoin light client contract.
        let res: String = seq_test_client
            .contract_call(
                BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
                BitcoinLightClient::get_block_hash(scanned).to_vec(),
                None,
            )
            .await
            .unwrap();
        let l1_block_hash = da.get_block_hash(scanned).await?;
        assert_eq!(
            l1_block_hash.to_raw_hash().to_byte_array().to_vec(),
            hex::decode(&res[2..]).unwrap(),
            "scanned L1 height should match a referenced light client block hash"
        );

        // Generate more DA blocks and confirm the persisted height advances.
        da.generate(5).await?;
        let next_target = da
            .get_finalized_height(Some(DEFAULT_FINALITY_DEPTH))
            .await?;
        assert!(next_target > target_l1_height);

        sequencer.wait_until_stopped().await?;
        sequencer.start(None, None).await?;
        sequencer.client.send_publish_batch_request().await?;
        sequencer.wait_for_l1_height(next_target, None).await?;

        let scanned_after = sequencer.client.ledger_get_last_scanned_l1_height().await?;
        assert_eq!(
            scanned_after, next_target,
            "sequencer should advance its scanned L1 height to the new finalized height"
        );
        assert!(
            scanned_after > scanned,
            "last scanned L1 height should advance as new DA blocks are produced"
        );

        Ok(())
    }
}

#[tokio::test]
async fn test_sequencer_last_scanned_l1_height() -> Result<()> {
    TestCaseRunner::new(SequencerLastScannedL1HeightTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// 1. Generate DA blocks while the sequencer is running.
/// 2. Drive L2 block production until the RPC reports the new finalized L1 height,
///    cross-checked against the Bitcoin light client contract.
/// 3. Generate more DA blocks and assert the reported height advances.
struct SequencerLastScannedL1HeightRunningTest;

#[async_trait]
impl TestCase for SequencerLastScannedL1HeightRunningTest {
    fn sequencer_config() -> SequencerConfig {
        // Avoid commitment churn interfering with DA block accounting during the test.
        SequencerConfig {
            max_l2_blocks_per_commitment: 1000,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let sequencer = f.sequencer.as_ref().unwrap();
        let da = f.bitcoin_nodes.get(0).unwrap();

        let seq_test_client = make_test_client(SocketAddr::new(
            sequencer.config.rpc_bind_host().parse()?,
            sequencer.config.rpc_bind_port(),
        ))
        .await?;

        // Generate DA blocks while the sequencer is running. Its DA block monitor
        // picks them up and they get folded into L2 blocks as we publish.
        da.generate(5).await?;
        let target_l1_height = da
            .get_finalized_height(Some(DEFAULT_FINALITY_DEPTH))
            .await?;

        // Drive block production until the sequencer has scanned up to the newly
        // finalized L1 height. Each published block folds in any newly detected DA
        // blocks and persists the last scanned L1 height (no restart involved).
        let scanned = drive_until_scanned(&sequencer.client, target_l1_height).await?;
        assert!(
            scanned > 0,
            "sequencer should report a non-zero last scanned L1 height"
        );
        assert_eq!(
            scanned, target_l1_height,
            "sequencer should have scanned up to the finalized L1 height during normal operation"
        );

        // The reported height must be a real L1 block the sequencer referenced in
        // the Bitcoin light client contract.
        let res: String = seq_test_client
            .contract_call(
                BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
                BitcoinLightClient::get_block_hash(scanned).to_vec(),
                None,
            )
            .await
            .unwrap();
        let l1_block_hash = da.get_block_hash(scanned).await?;
        assert_eq!(
            l1_block_hash.to_raw_hash().to_byte_array().to_vec(),
            hex::decode(&res[2..]).unwrap(),
            "scanned L1 height should match a referenced light client block hash"
        );

        // Generate more DA blocks and confirm the persisted height advances without
        // restarting the sequencer.
        da.generate(5).await?;
        let next_target = da
            .get_finalized_height(Some(DEFAULT_FINALITY_DEPTH))
            .await?;
        assert!(next_target > target_l1_height);

        let scanned_after = drive_until_scanned(&sequencer.client, next_target).await?;
        assert_eq!(
            scanned_after, next_target,
            "sequencer should advance its scanned L1 height to the new finalized height"
        );
        assert!(
            scanned_after > scanned,
            "last scanned L1 height should advance as new DA blocks are produced"
        );

        // Generate a single DA block, wait one second for the DA monitor to observe
        // it, publish one L2 block, and confirm the scanned height increased by
        // exactly 1.
        let before_single = sequencer.client.ledger_get_last_scanned_l1_height().await?;
        da.generate(1).await?;
        sleep(Duration::from_secs(1)).await;

        let head = sequencer.client.ledger_get_head_l2_block_height().await?;
        sequencer.client.send_publish_batch_request().await?;
        sequencer.client.wait_for_l2_block(head + 1, None).await?;

        let after_single = sequencer.client.ledger_get_last_scanned_l1_height().await?;
        assert_eq!(
            after_single,
            before_single + 1,
            "a single new DA block should increase the scanned L1 height by exactly 1"
        );

        Ok(())
    }
}

/// Publishes L2 blocks until the sequencer's reported last scanned L1 height
/// reaches `target`, returning the final scanned height.
async fn drive_until_scanned(client: &citrea_e2e::client::Client, target: u64) -> Result<u64> {
    for _ in 0..60 {
        let scanned = client.ledger_get_last_scanned_l1_height().await?;
        if scanned >= target {
            return Ok(scanned);
        }
        let head = client.ledger_get_head_l2_block_height().await?;
        client.send_publish_batch_request().await?;
        client.wait_for_l2_block(head + 1, None).await?;
        // Give the DA block monitor a chance to observe the newly finalized blocks.
        sleep(Duration::from_millis(200)).await;
    }
    anyhow::bail!("sequencer did not reach scanned L1 height {target}");
}

#[tokio::test]
async fn test_sequencer_last_scanned_l1_height_running() -> Result<()> {
    TestCaseRunner::new(SequencerLastScannedL1HeightRunningTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

/// Reads a block hash out of the Bitcoin light client contract. A height the sequencer
/// has not recorded reads back as all zeroes.
async fn light_client_block_hash(client: &TestClient, l1_height: u64) -> Result<[u8; 32]> {
    let res: String = client
        .contract_call(
            BITCOIN_LIGHT_CLIENT_CONTRACT_ADDRESS,
            BitcoinLightClient::get_block_hash(l1_height).to_vec(),
            None,
        )
        .await
        .unwrap();

    Ok(hex::decode(&res[2..])
        .unwrap()
        .try_into()
        .expect("light client block hash should be 32 bytes"))
}

/// Returns every `setBlockInfo` call included in the given L2 block range.
async fn set_block_info_calls(
    client: &TestClient,
    l2_heights: std::ops::RangeInclusive<u64>,
) -> Result<Vec<setBlockInfoCall>> {
    let mut calls = vec![];

    for l2_height in l2_heights {
        let block = client
            .eth_get_block_by_number_with_detail(Some(l2_height.into()))
            .await;
        let transactions = block
            .transactions
            .as_transactions()
            .expect("detailed block response should contain full transactions");

        for tx in transactions {
            if tx.to() == Some(BitcoinLightClient::address())
                && tx.input().starts_with(&setBlockInfoCall::SELECTOR)
            {
                assert_eq!(
                    tx.inner.signer(),
                    SYSTEM_SIGNER,
                    "setBlockInfo must be a system transaction"
                );
                calls.push(setBlockInfoCall::abi_decode(tx.input(), true)?);
            }
        }
    }

    Ok(calls)
}

/// How the sequencer runs into the stale DA tip.
enum StaleTip {
    /// It is already running and the stale tip arrives over the DA block monitor.
    WhileRunning,
    /// It comes up against a DA node that is already behind, so its whole view of L1 is
    /// the stale one and there is no earlier height in memory to compare against. Only
    /// the height read back out of the light client contract stands in the way.
    OnStartup,
}

/// A Bitcoin node that is catching up — after a restart of its own, or of the machine it
/// shares with the sequencer — answers with a tip below one the sequencer has already
/// folded into the Bitcoin light client contract. `setBlockInfo` takes no height, the
/// contract counts for itself, so recording such a block fails short header proof
/// verification and takes L2 block production down with it for as long as the node stays
/// behind. Neither may happen: L2 blocks keep coming, L1 stays put until the node is
/// caught up.
///
/// 1. Drive the sequencer until it has folded the finalized L1 tip into the contract.
/// 2. When testing a running sequencer, let its monitor cache a newer finalized tip
///    without producing an L2 block, leaving pending missed DA blocks.
/// 3. Invalidate DA blocks so the node reports a finalized height below the sequencer's
///    last good view, and let the sequencer meet it either way round.
/// 4. Assert the sequencer keeps producing L2 blocks and records nothing for the stale
///    tip.
/// 5. Restore the DA chain and assert the sequencer picks up where it left off.
async fn run_stale_da_tip_test(f: &mut TestFramework, stale_tip: StaleTip) -> Result<()> {
    let sequencer = f.sequencer.as_mut().unwrap();
    let da = f.bitcoin_nodes.get(0).unwrap();

    let seq_test_client = make_test_client(SocketAddr::new(
        sequencer.config.rpc_bind_host().parse()?,
        sequencer.config.rpc_bind_port(),
    ))
    .await?;

    // Catch the sequencer up with the finalized L1 tip.
    da.generate(5).await?;
    let target_l1_height = da
        .get_finalized_height(Some(DEFAULT_FINALITY_DEPTH))
        .await?;
    let scanned = drive_until_scanned(&sequencer.client, target_l1_height).await?;
    assert_eq!(scanned, target_l1_height);
    assert_eq!(
        light_client_block_hash(&seq_test_client, scanned + 1).await?,
        [0u8; 32],
        "nothing should be recorded above the scanned L1 height yet"
    );

    let last_good_finalized_height = match stale_tip {
        StaleTip::WhileRunning => {
            // Let the monitor observe a tip several blocks ahead of the light client,
            // creating pending missed DA blocks without giving the sequencer a production
            // request on which to process them.
            da.generate(5).await?;
            let pending_finalized_height = da
                .get_finalized_height(Some(DEFAULT_FINALITY_DEPTH))
                .await?;
            assert!(pending_finalized_height > scanned + 1);
            sleep(Duration::from_secs(1)).await;
            pending_finalized_height
        }
        StaleTip::OnStartup => scanned,
    };

    // Walk the DA node's tip backwards, so the finalized height it reports drops below
    // the last finalized height the sequencer observed.
    let invalidated = da.get_block_hash(da.get_block_count().await? - 2).await?;
    da.invalidate_block(&invalidated).await?;
    let stale_finalized_height = da
        .get_finalized_height(Some(DEFAULT_FINALITY_DEPTH))
        .await?;
    assert!(
        stale_finalized_height < last_good_finalized_height,
        "invalidating blocks should regress the finalized height"
    );
    if matches!(stale_tip, StaleTip::WhileRunning) {
        assert!(
            stale_finalized_height > scanned,
            "the regressed tip should remain ahead of the light client"
        );
    }

    match stale_tip {
        // Give the DA block monitor time to observe the stale tip.
        StaleTip::WhileRunning => sleep(Duration::from_secs(1)).await,
        StaleTip::OnStartup => sequencer.restart(None, None).await?,
    }

    // The sequencer keeps producing L2 blocks off its last good view of L1
    let head = sequencer.client.ledger_get_head_l2_block_height().await?;
    for i in 1..=3 {
        sequencer.client.send_publish_batch_request().await?;
        sequencer.client.wait_for_l2_block(head + i, None).await?;
    }

    assert!(
        set_block_info_calls(&seq_test_client, head + 1..=head + 3)
            .await?
            .is_empty(),
        "L2 blocks produced from a stale DA tip must not contain setBlockInfo"
    );

    assert_eq!(
        sequencer.client.ledger_get_last_scanned_l1_height().await?,
        scanned,
        "scanned L1 height must not move while the DA node is behind"
    );
    assert_eq!(
        light_client_block_hash(&seq_test_client, scanned + 1).await?,
        [0u8; 32],
        "a stale DA tip must not be written to the light client contract"
    );

    // Once the DA node is whole again, the sequencer picks up where it left off.
    da.reconsider_block(&invalidated).await?;
    da.generate(1).await?;
    let next_target = da
        .get_finalized_height(Some(DEFAULT_FINALITY_DEPTH))
        .await?;
    assert!(next_target > scanned);

    let recovery_l2_start = sequencer.client.ledger_get_head_l2_block_height().await?;
    let scanned_after = drive_until_scanned(&sequencer.client, next_target).await?;
    assert_eq!(scanned_after, next_target);
    let recovery_l2_end = sequencer.client.ledger_get_head_l2_block_height().await?;

    let mut expected_recovery_block_hashes = vec![];
    for l1_height in scanned + 1..=next_target {
        expected_recovery_block_hashes.push(
            da.get_block_hash(l1_height)
                .await?
                .to_raw_hash()
                .to_byte_array(),
        );
    }

    let recovery_set_block_info_calls =
        set_block_info_calls(&seq_test_client, recovery_l2_start + 1..=recovery_l2_end).await?;
    let actual_recovery_block_hashes: Vec<[u8; 32]> = recovery_set_block_info_calls
        .iter()
        .map(|call| call.blockHash.into())
        .collect();
    assert_eq!(
        actual_recovery_block_hashes, expected_recovery_block_hashes,
        "catching up must include exactly one ordered setBlockInfo call per recovered L1 block"
    );

    assert_eq!(
        light_client_block_hash(&seq_test_client, scanned + 1).await?,
        expected_recovery_block_hashes[0],
        "the light client should resume with the real L1 block above the scanned height"
    );

    Ok(())
}

/// Avoid commitment churn interfering with DA block accounting during the stale tip tests.
fn stale_da_tip_sequencer_config() -> SequencerConfig {
    SequencerConfig {
        max_l2_blocks_per_commitment: 1000,
        ..Default::default()
    }
}

struct SequencerStaleDaTipTest;

#[async_trait]
impl TestCase for SequencerStaleDaTipTest {
    fn sequencer_config() -> SequencerConfig {
        stale_da_tip_sequencer_config()
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        run_stale_da_tip_test(f, StaleTip::WhileRunning).await
    }
}

#[tokio::test]
async fn test_sequencer_stale_da_tip() -> Result<()> {
    TestCaseRunner::new(SequencerStaleDaTipTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}

struct SequencerStaleDaTipOnStartupTest;

#[async_trait]
impl TestCase for SequencerStaleDaTipOnStartupTest {
    fn sequencer_config() -> SequencerConfig {
        stale_da_tip_sequencer_config()
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        run_stale_da_tip_test(f, StaleTip::OnStartup).await
    }
}

#[tokio::test]
async fn test_sequencer_stale_da_tip_on_startup() -> Result<()> {
    TestCaseRunner::new(SequencerStaleDaTipOnStartupTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
