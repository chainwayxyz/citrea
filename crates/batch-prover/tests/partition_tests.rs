use std::sync::Arc;

use citrea_batch_prover::prover::{Prover, ProverRequest};
use citrea_common::BatchProverConfig;
use prover_services::{ParallelProverService, ProofGenMode};
use sov_db::ledger_db::LedgerDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::schema::tables::BATCH_PROVER_LEDGER_TABLES;
use sov_mock_da::{MockAddress, MockDaService};
use sov_mock_zkvm::MockZkvm;
use sov_prover_storage_manager::ProverStorageManager;
use tempfile::TempDir;
use tokio::sync::{broadcast, mpsc};

struct MockProverData {
    prover: Prover<MockDaService, LedgerDB, MockZkvm>,
    l1_signal_tx: mpsc::Sender<()>,
    l2_block_tx: broadcast::Sender<u64>,
    request_tx: mpsc::Sender<ProverRequest>,
}

fn create_mock_prover() -> MockProverData {
    let tmpdir = TempDir::new().unwrap();
    let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(
        tmpdir.path(),
        None,
        Some(
            BATCH_PROVER_LEDGER_TABLES
                .iter()
                .map(ToString::to_string)
                .collect(),
        ),
    ))
    .unwrap();
    let storage_manager = ProverStorageManager::new(sov_state::Config {
        path: tmpdir.path().to_path_buf(),
        db_max_open_files: None,
    })
    .unwrap();
    let da_service = Arc::new(MockDaService::new(
        MockAddress::from([1; 32]),
        tmpdir.path(),
    ));
    let vm = MockZkvm::new();
    let prover_service =
        Arc::new(ParallelProverService::new(da_service, vm, ProofGenMode::Execute, 1).unwrap());

    let (l1_signal_tx, l1_signal_rx) = mpsc::channel(1);
    let (l2_block_tx, l2_block_rx) = broadcast::channel(4);
    let (request_tx, request_rx) = mpsc::channel(4);

    let prover = Prover::new(
        BatchProverConfig::default(),
        ledger_db,
        storage_manager,
        prover_service,
        vec![1; 32],
        Default::default(),
        Default::default(),
        l1_signal_rx,
        l2_block_rx,
        request_rx,
    );

    MockProverData {
        prover,
        l1_signal_tx,
        l2_block_tx,
        request_tx,
    }
}

#[tokio::test]
async fn test_commitment_partition() {
    let MockProverData { prover, .. } = create_mock_prover();

    /*
    1. 1 commitment -> 1 partition
    2. 2 consecutive commitments -> 1 partition
    3. 2 consecutive commitments onebyone -> 2 partitions
    4. 3 commitments with index gap -> 2 partitions
    5. 3 commitments with spec change -> 2 partitions
    6. 3 commitments with high state diff -> 2 partitions
    7. 1 commitment with prev missing -> 0 partition
    8. 4 commitments (1,2,4,5) partitioned into 2 -> 1,2 and 5
    */
}
