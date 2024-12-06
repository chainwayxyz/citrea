use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use prover_services::{ParallelProverService, ProofGenMode};
use sov_db::ledger_db::LedgerDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_mock_da::{MockAddress, MockBlockHeader, MockDaService, MockDaSpec, MockHash};
use sov_mock_zkvm::MockZkvm;
use sov_rollup_interface::da::Time;
use sov_rollup_interface::zk::{BatchProofCircuitInput, Proof, ZkvmHost};
use sov_stf_runner::mock::MockStf;
use sov_stf_runner::ProverService;
use tokio::sync::oneshot;

#[tokio::test(flavor = "multi_thread")]
async fn test_successful_prover_execution() {
    let tmpdir = tempfile::tempdir().unwrap();
    let da_service = Arc::new(MockDaService::new(
        MockAddress::from([0; 32]),
        tmpdir.path(),
    ));

    let TestProver {
        prover_service, vm, ..
    } = make_new_prover(1, da_service);

    let header_hash = MockHash::from([0; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash)).unwrap(),
            vec![],
        ))
        .await;

    // Spawn mock proving in the background
    let rx = spawn_prove(prover_service.clone()).await;

    // Signal finish to 1st proof
    assert!(vm.finish_next_proof());

    let proofs = rx.await.unwrap();
    assert_eq!(proofs.len(), 1);

    // Check that the output is correct
    let header = extract_output_header(&proofs[0]);
    assert_eq!(header.hash, header_hash);

    let txs = prover_service.submit_proofs(proofs).await.unwrap();
    assert_eq!(txs.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_parallel_proofs_equal_to_limit() {
    let tmpdir = tempfile::tempdir().unwrap();
    let da_service = Arc::new(MockDaService::new(
        MockAddress::from([0; 32]),
        tmpdir.path(),
    ));

    // Parallel proof limit is 2
    let TestProver {
        prover_service, vm, ..
    } = make_new_prover(2, da_service);

    // 1st proof
    let header_hash_1 = MockHash::from([0; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_1)).unwrap(),
            vec![],
        ))
        .await;
    // 2nd proof
    let header_hash_2 = MockHash::from([1; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_2)).unwrap(),
            vec![],
        ))
        .await;

    // Spawn mock proving in the background
    let rx = spawn_prove(prover_service.clone()).await;

    // Signal finish to 1st proof
    assert!(vm.finish_next_proof());
    // Signal finish to 2nd proof
    assert!(vm.finish_next_proof());

    // Background proving job should be finished
    let proofs = rx.await.unwrap();
    assert_eq!(proofs.len(), 2);

    // Check that the output is correct and the order of proofs are same as the input
    let header_1 = extract_output_header(&proofs[0]);
    assert_eq!(header_1.hash, header_hash_1);
    let header_2 = extract_output_header(&proofs[1]);
    assert_eq!(header_2.hash, header_hash_2);

    let txs_and_proofs = prover_service.submit_proofs(proofs).await.unwrap();
    assert_eq!(txs_and_proofs.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_parallel_proofs_higher_than_limit() {
    let tmpdir = tempfile::tempdir().unwrap();
    let da_service = Arc::new(MockDaService::new(
        MockAddress::from([0; 32]),
        tmpdir.path(),
    ));

    // Parallel proof limit is 3
    let TestProver {
        prover_service, vm, ..
    } = make_new_prover(3, da_service);

    // 1st proof
    let header_hash_1 = MockHash::from([0; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_1)).unwrap(),
            vec![],
        ))
        .await;
    // 2nd proof
    let header_hash_2 = MockHash::from([1; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_2)).unwrap(),
            vec![],
        ))
        .await;
    // 3rd proof
    let header_hash_3 = MockHash::from([2; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_3)).unwrap(),
            vec![],
        ))
        .await;
    // 4th proof
    let header_hash_4 = MockHash::from([3; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_4)).unwrap(),
            vec![],
        ))
        .await;
    // 5th proof
    let header_hash_5 = MockHash::from([4; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_5)).unwrap(),
            vec![],
        ))
        .await;

    // Spawn mock proving in the background
    let rx = spawn_prove(prover_service.clone()).await;

    // Signal finish to 1st proof
    assert!(vm.finish_next_proof());

    // Emulate some execution
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Signal finish to 2nd proof
    assert!(vm.finish_next_proof());

    // Emulate some execution
    tokio::time::sleep(Duration::from_millis(100)).await;
    // Signal finish to 3rd proof
    assert!(vm.finish_next_proof());

    // Signal finish to 4th proof immediately
    assert!(vm.finish_next_proof());

    // Emulate some execution
    tokio::time::sleep(Duration::from_millis(500)).await;
    // Signal finish to 5th proof
    assert!(vm.finish_next_proof());

    // Background proving job should be finished
    let proofs = rx.await.unwrap();
    assert_eq!(proofs.len(), 5);

    // Check that the output is correct and the order of proofs are same as the input
    let header_1 = extract_output_header(&proofs[0]);
    assert_eq!(header_1.hash, header_hash_1);
    let header_2 = extract_output_header(&proofs[1]);
    assert_eq!(header_2.hash, header_hash_2);
    let header_3 = extract_output_header(&proofs[2]);
    assert_eq!(header_3.hash, header_hash_3);
    let header_4 = extract_output_header(&proofs[3]);
    assert_eq!(header_4.hash, header_hash_4);
    let header_5 = extract_output_header(&proofs[4]);
    assert_eq!(header_5.hash, header_hash_5);

    let txs_and_proofs = prover_service.submit_proofs(proofs).await.unwrap();
    assert_eq!(txs_and_proofs.len(), 5);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_parallel_proof_run() {
    let tmpdir = tempfile::tempdir().unwrap();
    let da_service = Arc::new(MockDaService::new(
        MockAddress::from([0; 32]),
        tmpdir.path(),
    ));

    // Parallel proof limit is 3
    let TestProver {
        prover_service, vm, ..
    } = make_new_prover(3, da_service);

    // 1st proof
    let header_hash_1 = MockHash::from([0; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_1)).unwrap(),
            vec![],
        ))
        .await;
    // 2nd proof
    let header_hash_2 = MockHash::from([1; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_2)).unwrap(),
            vec![],
        ))
        .await;

    // Spawn mock proving in the background
    let rx = spawn_prove(prover_service.clone()).await;

    // Signal finish to 1st proof
    assert!(vm.finish_next_proof());
    // Signal finish to 2nd proof
    assert!(vm.finish_next_proof());

    // Background proving job should be finished
    let proofs = rx.await.unwrap();
    assert_eq!(proofs.len(), 2);

    let txs_and_proofs = prover_service.submit_proofs(proofs).await.unwrap();
    assert_eq!(txs_and_proofs.len(), 2);

    // 1st proof
    let header_hash_3 = MockHash::from([2; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_3)).unwrap(),
            vec![],
        ))
        .await;
    // 2nd proof
    let header_hash_4 = MockHash::from([3; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_4)).unwrap(),
            vec![],
        ))
        .await;
    // 3rd proof
    let header_hash_5 = MockHash::from([4; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_5)).unwrap(),
            vec![],
        ))
        .await;

    // Spawn mock proving in the background
    let rx = spawn_prove(prover_service.clone()).await;

    // Signal finish to 1st proof
    assert!(vm.finish_next_proof());
    // Signal finish to 2nd proof
    assert!(vm.finish_next_proof());
    // Signal finish to 3rd proof
    assert!(vm.finish_next_proof());

    // Background proving job should be finished
    let proofs = rx.await.unwrap();
    assert_eq!(proofs.len(), 3);

    let txs_and_proofs = prover_service.submit_proofs(proofs).await.unwrap();
    assert_eq!(txs_and_proofs.len(), 3);
}

struct TestProver {
    prover_service: Arc<ParallelProverService<MockDaService, MockZkvm, MockStf>>,
    vm: MockZkvm,
}

fn make_new_prover(thread_pool_size: usize, da_service: Arc<MockDaService>) -> TestProver {
    let vm = MockZkvm::new();
    let proof_mode = ProofGenMode::Execute;

    let tmpdir = tempfile::tempdir().unwrap();
    let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(tmpdir.path(), None)).unwrap();
    TestProver {
        prover_service: Arc::new(
            ParallelProverService::new(
                da_service,
                vm.clone(),
                proof_mode,
                (),
                thread_pool_size,
                ledger_db,
            )
            .expect("Should be able to instantiate Prover service"),
        ),
        vm,
    }
}

fn make_transition_data(
    header_hash: MockHash,
) -> BatchProofCircuitInput<'static, [u8; 0], Vec<u8>, MockDaSpec, ()> {
    BatchProofCircuitInput {
        initial_state_root: [],
        inclusion_proof: [0; 32],
        prev_soft_confirmation_hash: [0; 32],
        completeness_proof: (),
        da_data: vec![],
        sequencer_commitments_range: (0, 0),
        da_block_header_of_commitments: MockBlockHeader {
            prev_hash: [0; 32].into(),
            hash: header_hash,
            txs_commitment: header_hash,
            height: 0,
            time: Time::now(),
            bits: 0,
        },
        soft_confirmations: VecDeque::new(),
        state_transition_witnesses: VecDeque::new(),
        da_block_headers_of_soft_confirmations: VecDeque::new(),
        sequencer_public_key: vec![],
        sequencer_da_public_key: vec![],
        preproven_commitments: vec![],
        final_state_root: [],
    }
}

async fn spawn_prove(
    prover_service: Arc<ParallelProverService<MockDaService, MockZkvm, MockStf>>,
) -> oneshot::Receiver<Vec<Proof>> {
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let proofs = prover_service.prove(vec![]).await.unwrap();
        tx.send(proofs).unwrap();
    });

    // Sleep some time to ensure that prover service started proving tasks
    tokio::time::sleep(Duration::from_millis(500)).await;

    rx
}

fn extract_output_header(proof: &Vec<u8>) -> MockBlockHeader {
    MockZkvm::extract_output::<
        MockDaSpec,
        BatchProofCircuitInput<'static, [u8; 0], Vec<u8>, MockDaSpec, ()>,
    >(proof)
    .unwrap()
    .da_block_header_of_commitments
}
