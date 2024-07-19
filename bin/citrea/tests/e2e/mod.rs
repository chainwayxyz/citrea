mod proving;
mod reopen;
mod sequencer_behaviour;
mod sequencer_replacement;
mod soft_confirmation_status;
mod syncing;
mod system_transactions;
mod tx_propagation;

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use citrea_evm::smart_contracts::SimpleStorageContract;
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::{Address, BlockNumberOrTag, U256};
use shared_backup_db::{PostgresConnector, SharedBackupDbConfig};
use sov_mock_da::{MockAddress, MockDaService};
use sov_rollup_interface::rpc::{LastVerifiedProofResponse, SoftConfirmationStatus};
use sov_rollup_interface::services::da::DaService;
use sov_stf_runner::ProverConfig;
use tokio::task::JoinHandle;

use crate::evm::{init_test_rollup, make_test_client};
use crate::test_client::TestClient;
use crate::test_helpers::{
    start_rollup, tempdir_with_children, wait_for_l1_block, wait_for_l2_block, wait_for_proof,
    wait_for_prover_l1_height, NodeMode,
};
use crate::{
    DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT, DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
    DEFAULT_PROOF_WAIT_DURATION, TEST_DATA_GENESIS_PATH,
};

struct TestConfig {
    seq_min_soft_confirmations: u64,
    deposit_mempool_fetch_limit: usize,
    sequencer_path: PathBuf,
    fullnode_path: PathBuf,
    da_path: PathBuf,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            seq_min_soft_confirmations: DEFAULT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
            deposit_mempool_fetch_limit: 10,
            sequencer_path: PathBuf::new(),
            fullnode_path: PathBuf::new(),
            da_path: PathBuf::new(),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_all_flow() {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "prover", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let prover_db_dir = storage_dir.path().join("prover").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let psql_db_name = "test_all_flow".to_owned();
    let db_test_client = PostgresConnector::new_test_client(psql_db_name.clone())
        .await
        .unwrap();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
            da_db_dir_cloned,
            4,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await;
    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let prover_node_task = tokio::spawn(async move {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(ProverConfig {
                proving_mode: sov_stf_runner::ProverGuestRunConfig::Execute,
                proof_sampling_number: 0,
                db_config: Some(SharedBackupDbConfig::default().set_db_name(psql_db_name)),
            }),
            NodeMode::Prover(seq_port),
            prover_db_dir,
            da_db_dir_cloned,
            4,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let prover_node_port = prover_node_port_rx.await.unwrap();

    let prover_node_test_client = make_test_client(prover_node_port).await;

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::FullNode(seq_port),
            fullnode_db_dir,
            da_db_dir_cloned,
            4,
            true,
            None,
            None,
            Some(true),
            DEFAULT_DEPOSIT_MEMPOOL_FETCH_LIMIT,
        )
        .await;
    });

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265").unwrap();

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await;

    da_service.publish_test_block().await.unwrap();
    wait_for_l1_block(&da_service, 2, None).await;

    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 1, None).await;

    // send one ether to some address
    let _pending = test_client
        .send_eth(addr, None, None, None, 1e18 as u128)
        .await
        .unwrap();
    // send one ether to some address
    let _pending = test_client
        .send_eth(addr, None, None, None, 1e18 as u128)
        .await
        .unwrap();
    test_client.send_publish_batch_request().await;
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 3, None).await;

    // send one ether to some address
    let _pending = test_client
        .send_eth(addr, None, None, None, 1e18 as u128)
        .await
        .unwrap();
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&test_client, 4, None).await;

    // Commitment
    wait_for_l1_block(&da_service, 3, None).await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        4,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    let commitments = prover_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(3)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments.len(), 1);

    assert_eq!(commitments[0].l2_start_block_number, 1);
    assert_eq!(commitments[0].l2_end_block_number, 4);

    assert_eq!(commitments[0].found_in_l1, 3);

    let third_block_hash = da_service.get_block_at(3).await.unwrap().header.hash;

    let commitments_hash = prover_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_hash(third_block_hash.0)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments_hash, commitments);

    let prover_proof = prover_node_test_client
        .ledger_get_proof_by_slot_height(3)
        .await;

    let db_proofs = db_test_client.get_all_proof_data().await.unwrap();

    assert_eq!(db_proofs.len(), 1);
    assert_eq!(
        db_proofs[0].state_transition.0.sequencer_da_public_key,
        prover_proof.state_transition.sequencer_da_public_key
    );
    assert_eq!(
        db_proofs[0].state_transition.0.sequencer_public_key,
        prover_proof.state_transition.sequencer_public_key
    );
    assert_eq!(db_proofs[0].l1_tx_id, prover_proof.l1_tx_id);

    // the proof will be in l1 block #4 because prover publishes it after the commitment and in mock da submitting proof and commitments creates a new block
    // For full node to see the proof, we publish another l2 block and now it will check #4 l1 block
    // 6th soft batch
    wait_for_l1_block(&da_service, 4, None).await;
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 6, None).await;

    // So the full node should see the proof in block 5
    wait_for_proof(&full_node_test_client, 4, Some(Duration::from_secs(120))).await;
    let full_node_proof = full_node_test_client
        .ledger_get_verified_proofs_by_slot_height(4)
        .await
        .unwrap();

    let LastVerifiedProofResponse {
        proof: last_proof,
        height: proof_l1_height,
    } = full_node_test_client
        .ledger_get_last_verified_proof()
        .await
        .unwrap();

    assert_eq!(prover_proof.proof, full_node_proof[0].proof);

    assert_eq!(proof_l1_height, 4);
    assert_eq!(last_proof.proof, full_node_proof[0].proof);
    assert_eq!(
        last_proof.state_transition,
        full_node_proof[0].state_transition
    );

    assert_eq!(
        prover_proof.state_transition,
        full_node_proof[0].state_transition
    );

    full_node_test_client
        .ledger_get_soft_confirmation_status(5)
        .await
        .unwrap()
        .unwrap();

    for i in 1..=4 {
        let status = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(status, SoftConfirmationStatus::Proven);
    }

    let balance = full_node_test_client
        .eth_get_balance(addr, None)
        .await
        .unwrap();
    assert_eq!(balance, U256::from(3e18 as u128));

    let balance = prover_node_test_client
        .eth_get_balance(addr, None)
        .await
        .unwrap();
    assert_eq!(balance, U256::from(3e18 as u128));

    // send one ether to some address
    let _pending = test_client
        .send_eth(addr, None, None, None, 1e18 as u128)
        .await
        .unwrap();
    // send one ether to some address
    let _pending = test_client
        .send_eth(addr, None, None, None, 1e18 as u128)
        .await
        .unwrap();

    for i in 7..=8 {
        test_client.send_publish_batch_request().await;
        wait_for_l2_block(&full_node_test_client, i, None).await;
    }

    // Commitment
    wait_for_l1_block(&da_service, 5, None).await;

    // wait here until we see from prover's rpc that it finished proving
    wait_for_prover_l1_height(
        &prover_node_test_client,
        5,
        Some(Duration::from_secs(DEFAULT_PROOF_WAIT_DURATION)),
    )
    .await;

    let commitments = prover_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(5)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments.len(), 1);

    let prover_proof_data = prover_node_test_client
        .ledger_get_proof_by_slot_height(5)
        .await;

    let db_proofs = db_test_client.get_all_proof_data().await.unwrap();

    assert_eq!(db_proofs.len(), 2);
    assert_eq!(
        db_proofs[1].state_transition.0.sequencer_da_public_key,
        prover_proof_data.state_transition.sequencer_da_public_key
    );
    assert_eq!(
        db_proofs[1].state_transition.0.sequencer_public_key,
        prover_proof_data.state_transition.sequencer_public_key
    );

    wait_for_proof(&full_node_test_client, 6, Some(Duration::from_secs(120))).await;
    let full_node_proof_data = full_node_test_client
        .ledger_get_verified_proofs_by_slot_height(6)
        .await
        .unwrap();

    let LastVerifiedProofResponse {
        proof: last_proof,
        height: proof_l1_height,
    } = full_node_test_client
        .ledger_get_last_verified_proof()
        .await
        .unwrap();
    assert_eq!(proof_l1_height, 6);
    assert_eq!(last_proof.proof, full_node_proof_data[0].proof);
    assert_eq!(
        last_proof.state_transition,
        full_node_proof_data[0].state_transition
    );

    assert_eq!(prover_proof_data.proof, full_node_proof_data[0].proof);
    assert_eq!(
        prover_proof_data.state_transition,
        full_node_proof_data[0].state_transition
    );

    let balance = full_node_test_client
        .eth_get_balance(addr, None)
        .await
        .unwrap();
    assert_eq!(balance, U256::from(5e18 as u128));

    let balance = prover_node_test_client
        .eth_get_balance(addr, None)
        .await
        .unwrap();
    assert_eq!(balance, U256::from(5e18 as u128));

    for i in 1..=8 {
        // print statuses
        let status = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(status, SoftConfirmationStatus::Proven);
    }

    // Synced up to the latest block
    wait_for_l2_block(&full_node_test_client, 8, Some(Duration::from_secs(60))).await;
    assert!(full_node_test_client.eth_block_number().await == 8);

    // Synced up to the latest commitment
    wait_for_l2_block(&prover_node_test_client, 8, Some(Duration::from_secs(60))).await;
    assert!(prover_node_test_client.eth_block_number().await == 8);

    seq_task.abort();
    prover_node_task.abort();
    full_node_task.abort();
}

/// Test RPC `ledger_getHeadSoftBatch`
#[tokio::test(flavor = "multi_thread")]
async fn test_ledger_get_head_soft_batch() {
    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();
    let fullnode_db_dir = storage_dir.path().join("full-node").to_path_buf();

    let config = TestConfig {
        da_path: da_db_dir.clone(),
        sequencer_path: sequencer_db_dir.clone(),
        fullnode_path: fullnode_db_dir.clone(),
        ..Default::default()
    };

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let da_db_dir_cloned = da_db_dir.clone();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_db_dir,
            da_db_dir_cloned,
            config.seq_min_soft_confirmations,
            true,
            None,
            None,
            Some(true),
            config.deposit_mempool_fetch_limit,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = init_test_rollup(seq_port).await;

    seq_test_client.send_publish_batch_request().await;
    seq_test_client.send_publish_batch_request().await;
    wait_for_l2_block(&seq_test_client, 2, None).await;

    let latest_block = seq_test_client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;

    let head_soft_batch = seq_test_client
        .ledger_get_head_soft_batch()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest_block.header.number.unwrap(), 2);
    assert_eq!(
        head_soft_batch.state_root.as_slice(),
        latest_block.header.state_root.as_slice()
    );
    assert_eq!(head_soft_batch.l2_height, 2);

    let head_soft_batch_height = seq_test_client
        .ledger_get_head_soft_batch_height()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head_soft_batch_height, 2);

    seq_task.abort();
}

async fn initialize_test(
    config: TestConfig,
) -> (
    Box<TestClient>, /* seq_test_client */
    Box<TestClient>, /* full_node_test_client */
    JoinHandle<()>,  /* seq_task */
    JoinHandle<()>,  /* full_node_task */
    Address,
) {
    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let db_path = config.da_path.clone();
    let sequencer_path = config.sequencer_path.clone();
    let fullnode_path = config.fullnode_path.clone();

    let db_path1 = db_path.clone();
    let seq_task = tokio::spawn(async move {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::SequencerNode,
            sequencer_path,
            db_path1,
            config.seq_min_soft_confirmations,
            true,
            None,
            None,
            Some(true),
            config.deposit_mempool_fetch_limit,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = make_test_client(seq_port).await;

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let db_path2 = db_path.clone();
    let full_node_task = tokio::spawn(async move {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            NodeMode::FullNode(seq_port),
            fullnode_path,
            db_path2,
            config.seq_min_soft_confirmations,
            true,
            None,
            None,
            Some(true),
            config.deposit_mempool_fetch_limit,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await;

    (
        seq_test_client,
        full_node_test_client,
        seq_task,
        full_node_task,
        Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
    )
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() {
        fs::create_dir(dst)?;
    }

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let entry_path = entry.path();
        let target_path = dst.join(entry.file_name());

        if entry_path.is_dir() {
            copy_dir_recursive(&entry_path, &target_path)?;
        } else {
            fs::copy(&entry_path, &target_path)?;
        }
    }
    Ok(())
}

async fn execute_blocks(
    sequencer_client: &TestClient,
    full_node_client: &TestClient,
    da_db_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let (contract_address, contract) = {
        let contract = SimpleStorageContract::default();
        let deploy_contract_req = sequencer_client
            .deploy_contract(contract.byte_code(), None)
            .await?;
        sequencer_client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .get_receipt()
            .await?
            .contract_address
            .unwrap();

        (contract_address, contract)
    };

    {
        let set_value_req = sequencer_client
            .contract_transaction(contract_address, contract.set_call_data(42), None)
            .await;
        sequencer_client.send_publish_batch_request().await;
        set_value_req.watch().await.unwrap();
    }

    sequencer_client.send_publish_batch_request().await;

    {
        for temp in 0..10 {
            let _set_value_req = sequencer_client
                .contract_transaction(contract_address, contract.set_call_data(78 + temp), None)
                .await;
        }
        sequencer_client.send_publish_batch_request().await;
    }

    {
        for _ in 0..200 {
            sequencer_client.send_publish_batch_request().await;
        }

        wait_for_l2_block(sequencer_client, 204, None).await;
    }

    let da_service = MockDaService::new(MockAddress::from([0; 32]), da_db_dir);
    da_service.publish_test_block().await.unwrap();

    {
        let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap();

        for _ in 0..300 {
            let _pending = sequencer_client
                .send_eth(addr, None, None, None, 0u128)
                .await
                .unwrap();
            sequencer_client.send_publish_batch_request().await;
        }
    }

    wait_for_l2_block(sequencer_client, 504, None).await;
    wait_for_l2_block(full_node_client, 504, None).await;

    let seq_last_block = sequencer_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    let full_node_last_block = full_node_client
        .eth_get_block_by_number_with_detail(Some(BlockNumberOrTag::Latest))
        .await;

    assert_eq!(seq_last_block.header.number.unwrap(), 504);
    assert_eq!(full_node_last_block.header.number.unwrap(), 504);

    assert_eq!(
        seq_last_block.header.state_root,
        full_node_last_block.header.state_root
    );
    assert_eq!(seq_last_block.header.hash, full_node_last_block.header.hash);

    Ok(())
}
