use std::collections::VecDeque;
use std::sync::Arc;

use prover_services::{ParallelProverService, ProofGenMode};
use sov_db::ledger_db::LedgerDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_mock_da::{MockAddress, MockBlockHeader, MockDaService, MockDaSpec, MockHash};
use sov_mock_zkvm::MockZkvm;
use sov_rollup_interface::da::Time;
use sov_rollup_interface::zk::BatchProofCircuitInput;
use sov_stf_runner::mock::MockStf;
use sov_stf_runner::ProverService;

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

    vm.make_proof();
    let proofs = prover_service.prove([0; 1].to_vec()).await.unwrap();

    prover_service.submit_proofs(proofs).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn test_parallel_proving_and_submit() {
    let tmpdir = tempfile::tempdir().unwrap();
    let da_service = Arc::new(MockDaService::new(
        MockAddress::from([0; 32]),
        tmpdir.path(),
    ));

    let TestProver {
        prover_service, vm, ..
    } = make_new_prover(2, da_service);

    let header_hash_1 = MockHash::from([0; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_1)).unwrap(),
            vec![],
        ))
        .await;

    let header_hash_2 = MockHash::from([1; 32]);
    prover_service
        .add_proof_data((
            borsh::to_vec(&make_transition_data(header_hash_2)).unwrap(),
            vec![],
        ))
        .await;

    vm.make_proof();
    let proofs = prover_service.prove([0; 1].to_vec()).await.unwrap();

    let txs_and_proofs = prover_service.submit_proofs(proofs).await.unwrap();
    assert_eq!(txs_and_proofs.len(), 2);
}

struct TestProver {
    prover_service: ParallelProverService<MockDaService, MockZkvm, MockStf>,
    vm: MockZkvm,
}

fn make_new_prover(thread_pool_size: usize, da_service: Arc<MockDaService>) -> TestProver {
    let vm = MockZkvm::new();
    let proof_mode = ProofGenMode::Execute;

    let tmpdir = tempfile::tempdir().unwrap();
    let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(tmpdir.path(), None)).unwrap();
    TestProver {
        prover_service: ParallelProverService::new(
            da_service,
            vm.clone(),
            proof_mode,
            (),
            thread_pool_size,
            ledger_db,
        )
        .expect("Should be able to instantiate Prover service"),
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
