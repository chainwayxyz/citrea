use std::net::SocketAddr;

use chainway_sequencer::experimental::ChainwaySequencer;
use demo_stf::genesis_config::GenesisPaths;
use sov_demo_rollup::MockDemoRollup;
use sov_mock_da::{MockAddress, MockDaConfig, MockDaService};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::default_signature::private_key::DefaultPrivateKey;
use sov_modules_rollup_blueprint::RollupBlueprint;
use sov_stf_runner::{RollupConfig, RollupProverConfig, RpcConfig, RunnerConfig, StorageConfig};
use tokio::sync::oneshot;

pub async fn start_rollup(
    rpc_reporting_channel: oneshot::Sender<SocketAddr>,
    genesis_paths: GenesisPaths,
    rollup_prover_config: RollupProverConfig,
) {
    println!("2");
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_path = temp_dir.path();

    let rollup_config = RollupConfig {
        storage: StorageConfig {
            path: temp_path.to_path_buf(),
        },
        runner: RunnerConfig {
            start_height: 0,
            rpc_config: RpcConfig {
                bind_host: "127.0.0.1".into(),
                bind_port: 0,
            },
        },
        da: MockDaConfig {
            sender_address: MockAddress::from([0; 32]),
        },
    };

    let mock_demo_rollup = MockDemoRollup {};
    println!("3");
    let rollup = mock_demo_rollup
        .create_new_rollup(&genesis_paths, rollup_config, rollup_prover_config)
        .await
        .unwrap();
    // ssequencer'a pasla run de
    println!("4");
    let da_service = MockDaService::new(MockAddress::new([0u8; 32]));
    let mut cs: ChainwaySequencer<DefaultContext, MockDaService, _> = ChainwaySequencer::new(
        rollup,
        da_service,
        DefaultPrivateKey::from_hex(
            "1212121212121212121212121212121212121212121212121212121212121212",
        )
        .unwrap(),
        0,
    );
    println!("5");
    cs.register_rpc_methods();
    cs.run(rpc_reporting_channel).await.unwrap();
    println!("6");

    // Close the tempdir explicitly to ensure that rustc doesn't see that it's unused and drop it unexpectedly
    temp_dir.close().unwrap();
}
