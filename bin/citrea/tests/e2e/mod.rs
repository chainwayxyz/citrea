mod proving;
mod reopen;
mod sequencer_behaviour;
mod sequencer_replacement;
mod soft_confirmation_status;
mod syncing;
mod system_transactions;

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use citrea_common::{BatchProverConfig, SequencerConfig};
use citrea_evm::smart_contracts::SimpleStorageContract;
use citrea_stf::genesis_config::GenesisPaths;
use reth_primitives::{Address, BlockNumberOrTag, U256};
use sov_mock_da::{MockAddress, MockDaService};
use sov_rollup_interface::rpc::{LastVerifiedBatchProofResponse, SoftConfirmationStatus};
use sov_rollup_interface::services::da::DaService;
use tokio::task::JoinHandle;

use crate::evm::{init_test_rollup, make_test_client};
use crate::test_client::TestClient;
use crate::test_helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l1_block,
    wait_for_l2_block, wait_for_proof, wait_for_prover_l1_height, NodeMode,
};
use crate::{
    TEST_DATA_GENESIS_PATH, TEST_SEND_NO_COMMITMENT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
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
            seq_min_soft_confirmations:
                TEST_SEND_NO_COMMITMENT_MIN_SOFT_CONFIRMATIONS_PER_COMMITMENT,
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

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let sequencer_config = SequencerConfig::default();
    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await.unwrap();
    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let (prover_node_port_tx, prover_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config =
        create_default_rollup_config(true, &prover_db_dir, &da_db_dir, NodeMode::Prover(seq_port));
    let prover_node_task = tokio::spawn(async {
        start_rollup(
            prover_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            Some(BatchProverConfig {
                proving_mode: sov_stf_runner::ProverGuestRunConfig::Execute,
                proof_sampling_number: 0,
                enable_recovery: true,
            }),
            None,
            rollup_config,
            None,
        )
        .await;
    });

    let prover_node_port = prover_node_port_rx.await.unwrap();

    let prover_node_test_client = make_test_client(prover_node_port).await.unwrap();

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &fullnode_db_dir,
        &da_db_dir,
        NodeMode::FullNode(seq_port),
    );
    let full_node_task = tokio::spawn(async {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            None,
        )
        .await;
    });

    let addr = Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92265").unwrap();

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await.unwrap();

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
    wait_for_prover_l1_height(&prover_node_test_client, 4, None)
        .await
        .unwrap();

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
        .ledger_get_batch_proofs_by_slot_height(3)
        .await
        .unwrap()[0]
        .clone();

    // the proof will be in l1 block #4 because prover publishes it after the commitment and in mock da submitting proof and commitments creates a new block
    // For full node to see the proof, we publish another l2 block and now it will check #4 l1 block
    // 6th soft confirmation
    wait_for_l1_block(&da_service, 4, None).await;
    test_client.send_publish_batch_request().await;
    wait_for_l2_block(&full_node_test_client, 6, None).await;

    // So the full node should see the proof in block 5
    wait_for_proof(&full_node_test_client, 4, Some(Duration::from_secs(120))).await;
    let full_node_proof = full_node_test_client
        .ledger_get_verified_batch_proofs_by_slot_height(4)
        .await
        .unwrap();

    let LastVerifiedBatchProofResponse {
        proof: last_proof,
        height: proof_l1_height,
    } = full_node_test_client
        .ledger_get_last_verified_batch_proof()
        .await
        .unwrap();

    assert_eq!(prover_proof.proof, full_node_proof[0].proof);

    assert_eq!(proof_l1_height, 4);
    assert_eq!(last_proof.proof, full_node_proof[0].proof);
    assert_eq!(last_proof.proof_output, full_node_proof[0].proof_output);

    assert_eq!(prover_proof.proof_output, full_node_proof[0].proof_output);

    full_node_test_client
        .ledger_get_soft_confirmation_status(5)
        .await
        .unwrap();

    for i in 1..=4 {
        let status = full_node_test_client
            .ledger_get_soft_confirmation_status(i)
            .await
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
    wait_for_prover_l1_height(&prover_node_test_client, 5, None)
        .await
        .unwrap();

    let commitments = prover_node_test_client
        .ledger_get_sequencer_commitments_on_slot_by_number(5)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(commitments.len(), 1);

    let prover_proof_data = prover_node_test_client
        .ledger_get_batch_proofs_by_slot_height(5)
        .await
        .unwrap()[0]
        .clone();

    wait_for_proof(&full_node_test_client, 6, Some(Duration::from_secs(120))).await;
    let full_node_proof_data = full_node_test_client
        .ledger_get_verified_batch_proofs_by_slot_height(6)
        .await
        .unwrap();

    let LastVerifiedBatchProofResponse {
        proof: last_proof,
        height: proof_l1_height,
    } = full_node_test_client
        .ledger_get_last_verified_batch_proof()
        .await
        .unwrap();
    assert_eq!(proof_l1_height, 6);
    assert_eq!(last_proof.proof, full_node_proof_data[0].proof);
    assert_eq!(
        last_proof.proof_output,
        full_node_proof_data[0].proof_output
    );

    assert_eq!(prover_proof_data.proof, full_node_proof_data[0].proof);
    assert_eq!(
        prover_proof_data.proof_output,
        full_node_proof_data[0].proof_output
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

/// Test RPC `ledger_getHeadSoftConfirmation`
#[tokio::test(flavor = "multi_thread")]
async fn test_ledger_get_head_soft_confirmation() {
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

    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let sequencer_config = SequencerConfig {
        min_soft_confirmations_per_commitment: config.seq_min_soft_confirmations,
        deposit_mempool_fetch_limit: config.deposit_mempool_fetch_limit,
        ..Default::default()
    };
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
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

    let head_soft_confirmation = seq_test_client
        .ledger_get_head_soft_confirmation()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(latest_block.header.number.unwrap(), 2);
    assert_eq!(
        head_soft_confirmation.state_root.as_slice(),
        latest_block.header.state_root.as_slice()
    );
    assert_eq!(head_soft_confirmation.l2_height, 2);

    let head_soft_confirmation_height = seq_test_client
        .ledger_get_head_soft_confirmation_height()
        .await
        .unwrap();
    assert_eq!(head_soft_confirmation_height, 2);

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

    let fullnode_path = config.fullnode_path.clone();

    let sequencer_config = SequencerConfig {
        min_soft_confirmations_per_commitment: config.seq_min_soft_confirmations,
        deposit_mempool_fetch_limit: config.deposit_mempool_fetch_limit,
        ..Default::default()
    };
    let rollup_config = create_default_rollup_config(
        true,
        &config.sequencer_path,
        &config.da_path,
        NodeMode::SequencerNode,
    );
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let seq_test_client = make_test_client(seq_port).await.unwrap();

    let (full_node_port_tx, full_node_port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &fullnode_path,
        &config.da_path,
        NodeMode::FullNode(seq_port),
    );
    let full_node_task = tokio::spawn(async {
        start_rollup(
            full_node_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            None,
        )
        .await;
    });

    let full_node_port = full_node_port_rx.await.unwrap();
    let full_node_test_client = make_test_client(full_node_port).await.unwrap();

    (
        seq_test_client,
        full_node_test_client,
        seq_task,
        full_node_task,
        Address::from_str("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").unwrap(),
    )
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

/// Deploy pre-fork contract, activate a fork and then check fetching the contract's code
/// through RPC to make sure that the actual code is fetched properly pre and post fork.
#[tokio::test(flavor = "multi_thread")]
async fn test_offchain_contract_storage() {
    // citrea::initialize_logging(tracing::Level::DEBUG);

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "prover", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let sequencer_config = SequencerConfig::default();
    let rollup_config =
        create_default_rollup_config(true, &sequencer_db_dir, &da_db_dir, NodeMode::SequencerNode);
    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(sequencer_config),
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let sequencer_client = make_test_client(seq_port).await.unwrap();

    sequencer_client.send_publish_batch_request().await;
    wait_for_l2_block(&sequencer_client, 1, None).await;

    let (contract_address, contract, runtime_code) = {
        let contract = SimpleStorageContract::default();
        let runtime_code = sequencer_client
            .deploy_contract_call(contract.byte_code(), None)
            .await
            .unwrap();
        let deploy_contract_req = sequencer_client
            .deploy_contract(contract.byte_code(), None)
            .await
            .unwrap();
        sequencer_client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .get_receipt()
            .await
            .unwrap()
            .contract_address
            .unwrap();

        (contract_address, contract, runtime_code)
    };

    {
        let set_value_req = sequencer_client
            .contract_transaction(contract_address, contract.set_call_data(42), None)
            .await;
        sequencer_client.send_publish_batch_request().await;
        set_value_req.watch().await.unwrap();
    }

    let code = sequencer_client
        .eth_get_code(contract_address, None)
        .await
        .unwrap();

    assert_eq!(code.to_vec()[..runtime_code.len()], runtime_code.to_vec());

    // reach the block at which the fork will be activated
    for _ in 3..=100 {
        sequencer_client.send_publish_batch_request().await;
    }

    // This should access the `code` and copy code over to `offchain_code` in EVM
    let code = sequencer_client
        .eth_get_code(contract_address, None)
        .await
        .unwrap();
    assert_eq!(code.to_vec()[..runtime_code.len()], runtime_code.to_vec());

    // Execute transaction on the contract living in `offchain_code`
    {
        let set_value_req = sequencer_client
            .contract_transaction(contract_address, contract.set_call_data(50), None)
            .await;
        sequencer_client.send_publish_batch_request().await;
        set_value_req.watch().await.unwrap();
    }

    let code = sequencer_client
        .eth_get_code(contract_address, None)
        .await
        .unwrap();
    assert_eq!(code.to_vec()[..runtime_code.len()], runtime_code.to_vec());

    // Deploy a contract post-fork
    let (contract_address, contract) = {
        let contract = SimpleStorageContract::default();
        let deploy_contract_req = sequencer_client
            .deploy_contract(contract.byte_code(), None)
            .await
            .unwrap();
        sequencer_client.send_publish_batch_request().await;

        let contract_address = deploy_contract_req
            .get_receipt()
            .await
            .unwrap()
            .contract_address
            .unwrap();

        (contract_address, contract)
    };

    {
        let set_value_req = sequencer_client
            .contract_transaction(contract_address, contract.set_call_data(60), None)
            .await;
        sequencer_client.send_publish_batch_request().await;
        set_value_req.watch().await.unwrap();
    }
    seq_task.abort();
}
