use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use prover_services::{ParallelProverService, ProofData, ProofGenMode};
use sov_mock_da::{MockAddress, MockBlockHeader, MockDaService, MockDaSpec, MockHash};
use sov_mock_zkvm::MockZkvm;
use sov_rollup_interface::da::Time;
use sov_rollup_interface::zk::batch_proof::input::BatchProofCircuitInput;
use sov_rollup_interface::zk::{Proof, ReceiptType, ZkvmHost};
use sov_state::Witness;
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
    // Spawn mock proving in the background
    let rx = start_proof(&prover_service, header_hash).await;

    // Signal finish to 1st proof
    assert!(vm.finish_next_proof());

    let proof = rx.await.unwrap();

    // Check that the output is correct
    let header = extract_output_header(&proof);
    assert_eq!(header.hash, header_hash);

    prover_service.submit_proof(proof).await.unwrap();
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
    let rx_1 = start_proof(&prover_service, header_hash_1).await;
    // 2nd proof
    let header_hash_2 = MockHash::from([1; 32]);
    let rx_2 = start_proof(&prover_service, header_hash_2).await;

    // Signal finish to 1st proof
    assert!(vm.finish_next_proof());
    let proof_1 = rx_1.await.unwrap();
    // Signal finish to 2nd proof
    assert!(vm.finish_next_proof());
    let proof_2 = rx_2.await.unwrap();

    // Check that the output is correct and the order of proofs are same as the input
    let header_1 = extract_output_header(&proof_1);
    assert_eq!(header_1.hash, header_hash_1);
    let header_2 = extract_output_header(&proof_2);
    assert_eq!(header_2.hash, header_hash_2);

    let txs_and_proofs = prover_service
        .submit_proofs(vec![proof_1, proof_2])
        .await
        .unwrap();
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
    let rx_1 = start_proof(&prover_service, header_hash_1).await;
    // 2nd proof
    let header_hash_2 = MockHash::from([1; 32]);
    let rx_2 = start_proof(&prover_service, header_hash_2).await;
    // 3rd proof
    let header_hash_3 = MockHash::from([2; 32]);
    let rx_3 = start_proof(&prover_service, header_hash_3).await;
    // 4th proof should not start and timeout
    let header_hash_4 = MockHash::from([3; 32]);
    let timeout = tokio::time::timeout(
        Duration::from_secs(1),
        start_proof(&prover_service, header_hash_4),
    )
    .await;
    assert!(timeout.is_err());

    // Signal finish to 1st proof
    assert!(vm.finish_next_proof());
    let proof_1 = rx_1.await.unwrap();

    // 4th proof should now be able to start
    let rx_4 = start_proof(&prover_service, header_hash_4).await;

    // Signal finish to 2nd proof
    assert!(vm.finish_next_proof());
    let proof_2 = rx_2.await.unwrap();

    // Signal finish to 3rd proof
    assert!(vm.finish_next_proof());
    let proof_3 = rx_3.await.unwrap();

    // Signal finish to 4th proof immediately
    assert!(vm.finish_next_proof());
    let proof_4 = rx_4.await.unwrap();

    // Check that the output is correct and the order of proofs are same as the input
    let header_1 = extract_output_header(&proof_1);
    assert_eq!(header_1.hash, header_hash_1);
    let header_2 = extract_output_header(&proof_2);
    assert_eq!(header_2.hash, header_hash_2);
    let header_3 = extract_output_header(&proof_3);
    assert_eq!(header_3.hash, header_hash_3);
    let header_4 = extract_output_header(&proof_4);
    assert_eq!(header_4.hash, header_hash_4);

    let txs_and_proofs = prover_service
        .submit_proofs(vec![proof_1, proof_2, proof_3, proof_4])
        .await
        .unwrap();
    assert_eq!(txs_and_proofs.len(), 4);
}

struct TestProver {
    prover_service: Arc<ParallelProverService<MockDaService, MockZkvm>>,
    vm: MockZkvm,
}

fn make_new_prover(thread_pool_size: usize, da_service: Arc<MockDaService>) -> TestProver {
    let vm = MockZkvm::new();
    let proof_mode = ProofGenMode::Execute;

    TestProver {
        prover_service: Arc::new(
            ParallelProverService::new(da_service, vm.clone(), proof_mode, thread_pool_size)
                .expect("Should be able to instantiate Prover service"),
        ),
        vm,
    }
}

fn make_transition_data(header_hash: MockHash) -> BatchProofCircuitInput<'static, MockDaSpec, ()> {
    BatchProofCircuitInput {
        initial_state_root: [0; 32],
        inclusion_proof: [0; 32],
        prev_soft_confirmation_hash: [0; 32],
        completeness_proof: Vec::new(),
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
        l2_blocks: VecDeque::new(),
        state_transition_witnesses: VecDeque::new(),
        da_block_headers_of_l2_blocks: VecDeque::new(),
        sequencer_public_key: vec![],
        sequencer_da_public_key: vec![],
        preproven_commitments: vec![],
        short_header_proofs: VecDeque::new(),
        final_state_root: [0; 32],
        sequencer_commitments: vec![],
        cache_prune_l2_heights: vec![],
        last_l1_hash_witness: Witness::default(),
        // Update this after you get the input from this function
        previous_sequencer_commitment: None,
    }
}

fn extract_output_header(proof: &Vec<u8>) -> MockBlockHeader {
    MockZkvm::extract_output::<BatchProofCircuitInput<'static, MockDaSpec, ()>>(proof)
        .unwrap()
        .da_block_header_of_commitments
}

async fn start_proof(
    prover_service: &ParallelProverService<MockDaService, MockZkvm>,
    header_hash: MockHash,
) -> oneshot::Receiver<Proof> {
    // Spawn mock proving in the background
    let rx = prover_service
        .start_proving(
            ProofData {
                input: borsh::to_vec(&make_transition_data(header_hash)).unwrap(),
                assumptions: vec![],
                elf: vec![],
            },
            ReceiptType::Groth16,
        )
        .await;

    // Ensure inner proving task is initialized
    tokio::time::sleep(Duration::from_millis(100)).await;

    rx
}
