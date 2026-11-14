//! Checks that a sequencer and a full node move through every fork at its activation height.
//!
//! Nodes run in-process, so the fork list set here applies to all of them. Guests are compiled
//! with the fork list of their network, so this test runs no prover. Replaying commitments
//! across forks is covered by `test_apply_sequencer_commitments_across_forks`.
use std::str::FromStr;
use std::time::Duration;

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy_primitives::{Address, Bytes, U256};
use alloy_rpc_types::{Authorization, BlockNumberOrTag};
use citrea_evm::smart_contracts::{
    P256VerifyCallerContract, SchnorrVerifyCallerContract, SimpleStorageContract,
};
use citrea_primitives::forks::{fork_from_block_number, get_forks, FORKS};
use sov_mock_da::{MockAddress, MockDaService};
use sov_rollup_interface::fork::Fork;
use sov_rollup_interface::spec::SpecId;

use super::{initialize_test, TestConfig};
use crate::common::client::TestClient;
use crate::common::helpers::{tempdir_with_children, wait_for_commitment, wait_for_l2_block};

const KUMQUAT_HEIGHT: u64 = 10;
const TANGERINE_HEIGHT: u64 = 20;
const TANGELO_HEIGHT: u64 = 30;
const TANGELO_SELFDESTRUCT_FIX_HEIGHT: u64 = 40;
const POMELO_HEIGHT: u64 = 50;

const TEST_FORKS: &[Fork] = &[
    Fork::new(SpecId::Genesis, 0),
    Fork::new(SpecId::Kumquat, KUMQUAT_HEIGHT),
    Fork::new(SpecId::Tangerine, TANGERINE_HEIGHT),
    Fork::new(SpecId::Tangelo, TANGELO_HEIGHT),
    Fork::new(
        SpecId::TangeloSelfdestructFix,
        TANGELO_SELFDESTRUCT_FIX_HEIGHT,
    ),
    Fork::new(SpecId::Pomelo, POMELO_HEIGHT),
];

const MAX_L2_BLOCKS_PER_COMMITMENT: u64 = 5;

const SCHNORR_INPUT: &str = "0xD69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B94DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B969670300000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4";
const P256_INPUT: &str = "b5a77e7a90aa14e0bf5f337f06f597148676424fae26e175c6e5621c34351955289f319789da424845c9eac935245fcddd805950e2f02506d09be7e411199556d262144475b1fa46ad85250728c600c53dfd10f8b3f4adf140e27241aec3c2da3a81046703fccf468b48b145f939efdbb96c3786db712b3113bb2488ef286cdcef8afe82d200a5bb36b5462166e8ce77f2d831a52ef2135b2af188110beaefb1";

const SCHNORR_PRECOMPILE: &str = "0x0000000000000000000000000000000000000200";
const P256_PRECOMPILE: &str = "0x0000000000000000000000000000000000000100";
const CALL_SUCCESS: &str = "0x0000000000000000000000000000000000000000000000000000000000000001";

struct TestContracts {
    schnorr_caller: Address,
    p256_caller: Address,
}

async fn deploy_test_contracts(client: &TestClient) -> TestContracts {
    let _deploy_tx = client
        .deploy_contract(SimpleStorageContract::default().byte_code(), None)
        .await
        .unwrap();
    let _deploy_tx = client
        .deploy_contract(SchnorrVerifyCallerContract::default().byte_code(), None)
        .await
        .unwrap();
    let _deploy_tx = client
        .deploy_contract(P256VerifyCallerContract::default().byte_code(), None)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(1)).await;
    client.send_publish_batch_request().await;
    wait_for_l2_block(client, 1, None).await;

    TestContracts {
        schnorr_caller: client.from_addr.create(1),
        p256_caller: client.from_addr.create(2),
    }
}

async fn advance_to(client: &TestClient, height: u64) {
    let head = client.ledger_get_head_l2_block_height().await.unwrap();
    assert!(head <= height, "Already past height {height}, at {head}");
    for _ in head..height {
        client.send_publish_batch_request().await;
    }
    wait_for_l2_block(client, height, None).await;
}

async fn assert_active_spec(client: &TestClient, spec_id: SpecId) {
    let head = client.ledger_get_head_l2_block_height().await.unwrap();
    assert_eq!(fork_from_block_number(head).spec_id, spec_id);
}

async fn send_eip7702_transaction_and_get_code(client: &TestClient) -> anyhow::Result<Bytes> {
    let authority_signer = PrivateKeySigner::random();

    let authorization = Authorization {
        address: client.from_addr.create(0),
        chain_id: U256::from(client.chain_id),
        nonce: 0,
    };
    let signature = authority_signer
        .sign_hash_sync(&authorization.signature_hash())
        .unwrap();

    let tx = client
        .send_eip7702_transaction(
            Address::ZERO,
            vec![],
            None,
            vec![authorization.into_signed(signature)],
        )
        .await?;

    tokio::time::sleep(Duration::from_secs(1)).await;
    client.send_publish_batch_request().await;

    let receipt = tx.get_receipt().await.unwrap();
    assert!(receipt.status());

    client.eth_get_code(authority_signer.address(), None).await
}

/// Schnorr, P256 and EIP-7702 only exist from Tangerine on.
async fn assert_tangerine_features_rejected(client: &TestClient, contracts: &TestContracts) {
    let schnorr_result = client
        .contract_call::<String>(
            contracts.schnorr_caller,
            SchnorrVerifyCallerContract::default()
                .call_schnorr_verify(Bytes::from_str(SCHNORR_INPUT).unwrap()),
            None,
        )
        .await;
    assert!(
        schnorr_result.is_err(),
        "Schnorr must not be available before Tangerine"
    );

    let p256_result = client
        .contract_call::<String>(
            contracts.p256_caller,
            P256VerifyCallerContract::default()
                .call_p256_verify(Bytes::from_str(P256_INPUT).unwrap()),
            None,
        )
        .await;
    assert!(
        p256_result.is_err(),
        "P256 must not be available before Tangerine"
    );

    assert!(
        send_eip7702_transaction_and_get_code(client).await.is_err(),
        "EIP-7702 txs must fail before Tangerine"
    );
}

async fn assert_tangerine_features_available(client: &TestClient, contracts: &TestContracts) {
    // Rejected transactions consumed local nonces.
    client.sync_nonce().await;

    let schnorr_input = Bytes::from_str(SCHNORR_INPUT).unwrap();
    let schnorr_tx = client
        .contract_transaction(
            contracts.schnorr_caller,
            SchnorrVerifyCallerContract::default().call_schnorr_verify(schnorr_input.clone()),
            None,
        )
        .await;
    client.send_publish_batch_request().await;
    assert!(schnorr_tx.get_receipt().await.unwrap().status());
    assert_eq!(
        client
            .eth_get_storage_at(contracts.schnorr_caller, U256::ZERO, None)
            .await
            .unwrap(),
        U256::from(1)
    );
    let schnorr_call = client
        .contract_call::<String>(
            Address::from_str(SCHNORR_PRECOMPILE).unwrap(),
            schnorr_input.to_vec(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(schnorr_call, CALL_SUCCESS);

    let p256_input = Bytes::from_str(P256_INPUT).unwrap();
    let p256_tx = client
        .contract_transaction(
            contracts.p256_caller,
            P256VerifyCallerContract::default().call_p256_verify(p256_input.clone()),
            None,
        )
        .await;
    client.send_publish_batch_request().await;
    assert!(p256_tx.get_receipt().await.unwrap().status());
    assert_eq!(
        client
            .eth_get_storage_at(contracts.p256_caller, U256::ZERO, None)
            .await
            .unwrap(),
        U256::from(1)
    );
    let p256_call = client
        .contract_call::<String>(
            Address::from_str(P256_PRECOMPILE).unwrap(),
            p256_input.to_vec(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(p256_call, CALL_SUCCESS);

    assert!(
        send_eip7702_transaction_and_get_code(client).await.is_ok(),
        "EIP-7702 txs must succeed after Tangerine"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_fork_activation() -> anyhow::Result<()> {
    // Nodes keep this list: `use_network_forks` ignores a second set under `testing`.
    let _ = FORKS.set(TEST_FORKS);
    assert_eq!(
        get_forks(),
        TEST_FORKS,
        "Forks are global, run this test in its own process with nextest"
    );

    let storage_dir = tempdir_with_children(&["DA", "sequencer", "full-node"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();

    let (seq_client, full_node_client, seq_task, full_node_task, _) = initialize_test(TestConfig {
        da_path: da_db_dir.clone(),
        sequencer_path: storage_dir.path().join("sequencer").to_path_buf(),
        fullnode_path: storage_dir.path().join("full-node").to_path_buf(),
        seq_max_l2_blocks: MAX_L2_BLOCKS_PER_COMMITMENT,
        ..Default::default()
    })
    .await;
    let da_service = MockDaService::new(MockAddress::from([0; 32]), &da_db_dir);

    let contracts = deploy_test_contracts(&seq_client).await;

    assert_active_spec(&seq_client, SpecId::Genesis).await;
    assert_tangerine_features_rejected(&seq_client, &contracts).await;

    advance_to(&seq_client, KUMQUAT_HEIGHT).await;
    assert_active_spec(&seq_client, SpecId::Kumquat).await;
    assert_tangerine_features_rejected(&seq_client, &contracts).await;

    // Far more blocks than a commitment needs, but proving only starts at Tangerine.
    advance_to(&seq_client, TANGERINE_HEIGHT - 1).await;
    let l1_height_before_tangerine = da_service.get_height().await;

    advance_to(&seq_client, TANGERINE_HEIGHT).await;
    assert_active_spec(&seq_client, SpecId::Tangerine).await;
    assert_tangerine_features_available(&seq_client, &contracts).await;

    advance_to(&seq_client, TANGERINE_HEIGHT + MAX_L2_BLOCKS_PER_COMMITMENT).await;
    let commitments = wait_for_commitment(&da_service, l1_height_before_tangerine + 1, None).await;
    // Index 1 means no commitment was sent while the blocks before Tangerine were produced.
    let first_commitment = &commitments[0];
    assert_eq!(first_commitment.index, 1);
    assert!(first_commitment.l2_end_block_number >= TANGERINE_HEIGHT);

    advance_to(&seq_client, TANGELO_HEIGHT).await;
    assert_active_spec(&seq_client, SpecId::Tangelo).await;

    advance_to(&seq_client, TANGELO_SELFDESTRUCT_FIX_HEIGHT).await;
    assert_active_spec(&seq_client, SpecId::TangeloSelfdestructFix).await;

    advance_to(&seq_client, POMELO_HEIGHT).await;
    assert_active_spec(&seq_client, SpecId::Pomelo).await;
    assert_tangerine_features_available(&seq_client, &contracts).await;

    // The full node re-executes every block, so a spec mismatch changes its state root.
    let head = seq_client.ledger_get_head_l2_block_height().await.unwrap();
    wait_for_l2_block(&full_node_client, head, None).await;
    for height in [
        KUMQUAT_HEIGHT,
        TANGERINE_HEIGHT,
        TANGELO_HEIGHT,
        TANGELO_SELFDESTRUCT_FIX_HEIGHT,
        POMELO_HEIGHT,
        head,
    ] {
        let seq_block = seq_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Number(height)))
            .await;
        let full_node_block = full_node_client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Number(height)))
            .await;
        assert_eq!(
            seq_block.header.state_root, full_node_block.header.state_root,
            "State root mismatch at height {height}"
        );
    }

    seq_task.graceful_shutdown();
    full_node_task.graceful_shutdown();

    Ok(())
}
