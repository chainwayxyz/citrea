use std::collections::HashMap;
use std::sync::Arc;

use citrea_fullnode::CitreaFullnode;
use sov_db::ledger_db::LedgerDB;
use sov_db::rocks_db_config::RocksdbConfig;
use sov_mock_da::{MockAddress, MockDaConfig, MockDaService, MockDaSpec, MockValidityCond};
use sov_mock_zkvm::{MockCodeCommitment, MockZkvm};
use sov_prover_storage_manager::ProverStorageManager;
use sov_rollup_interface::fork::{Fork, ForkManager};
use sov_rollup_interface::spec::SpecId;
use sov_state::DefaultStorageSpec;
use sov_stf_runner::{
    FullNodeConfig, InitVariant, RollupPublicKeys, RpcConfig, RunnerConfig, StorageConfig,
};

mod hash_stf;

use hash_stf::HashStf;
use tokio::sync::broadcast;

type MockInitVariant =
    InitVariant<HashStf<MockValidityCond>, MockZkvm<MockValidityCond>, MockDaSpec>;

type S = DefaultStorageSpec;
type StorageManager = ProverStorageManager<MockDaSpec, S>;

#[tokio::test(flavor = "multi_thread")]
async fn init_and_restart() {
    let tmpdir = tempfile::tempdir().unwrap();
    let genesis_params = vec![1, 2, 3, 4, 5];
    let init_variant: MockInitVariant = InitVariant::Genesis(genesis_params);

    let state_root_after_genesis = {
        let runner = initialize_runner(tmpdir.path(), init_variant);
        *runner.get_state_root()
    };

    let init_variant_2: MockInitVariant =
        InitVariant::Initialized((state_root_after_genesis, [0; 32]));

    let runner_2 = initialize_runner(tmpdir.path(), init_variant_2);

    let state_root_2 = *runner_2.get_state_root();

    assert_eq!(state_root_after_genesis, state_root_2);
}

fn initialize_runner(
    storage_path: &std::path::Path,
    init_variant: MockInitVariant,
) -> CitreaFullnode<
    HashStf<MockValidityCond>,
    StorageManager,
    MockDaService,
    MockZkvm<MockValidityCond>,
    sov_modules_api::default_context::DefaultContext,
    LedgerDB,
> {
    let forks = vec![Fork::new(SpecId::Genesis, 0)];
    let da_storage_path = storage_path.join("da").to_path_buf();
    let rollup_storage_path = storage_path.join("rollup").to_path_buf();

    if !std::path::Path::new(&da_storage_path).exists() {
        let _ = std::fs::create_dir(da_storage_path.clone());
    }
    if !std::path::Path::new(&rollup_storage_path).exists() {
        let _ = std::fs::create_dir(rollup_storage_path.clone());
    }

    let address = MockAddress::new([11u8; 32]);
    let rollup_config = FullNodeConfig::<MockDaConfig> {
        storage: StorageConfig {
            path: rollup_storage_path.clone(),
            db_max_open_files: None,
        },
        rpc: RpcConfig {
            bind_host: "127.0.0.1".to_string(),
            bind_port: 0,
            max_connections: 100,
            max_request_body_size: 10 * 1024 * 1024,
            max_response_body_size: 10 * 1024 * 1024,
            batch_requests_limit: 50,
            enable_subscriptions: true,
            max_subscriptions_per_connection: 100,
        },
        runner: Some(RunnerConfig {
            sequencer_client_url: "http://127.0.0.1:4444".to_string(),
            include_tx_body: true,
            accept_public_input_as_proven: None,
            sync_blocks_count: 10,
            pruning_mode: Default::default(),
        }),
        da: MockDaConfig {
            sender_address: address,
            db_path: da_storage_path.clone(),
        },
        public_keys: RollupPublicKeys {
            sequencer_public_key: vec![],
            sequencer_da_pub_key: vec![],
            prover_da_pub_key: vec![],
        },
    };

    let da_service = MockDaService::new(address, &da_storage_path);

    let ledger_db =
        LedgerDB::with_config(&RocksdbConfig::new(rollup_storage_path.as_path(), None)).unwrap();

    let stf = HashStf::<MockValidityCond>::new();

    let storage_config = sov_state::config::Config {
        path: rollup_storage_path.to_path_buf(),
        db_max_open_files: None,
    };
    let storage_manager = ProverStorageManager::new(storage_config).unwrap();

    // let vm = MockZkvm::new(MockValidityCond::default());
    // let verifier = MockDaVerifier::default();

    let fork_manager = ForkManager::new(forks, 0);

    let mut code_commitments_by_spec = HashMap::new();
    code_commitments_by_spec.insert(SpecId::Genesis, MockCodeCommitment([1u8; 32]));

    CitreaFullnode::new(
        rollup_config.runner.unwrap(),
        rollup_config.public_keys,
        rollup_config.rpc,
        Arc::new(da_service),
        ledger_db,
        stf,
        storage_manager,
        init_variant,
        code_commitments_by_spec,
        fork_manager,
        broadcast::channel(1).0,
    )
    .unwrap()
}
