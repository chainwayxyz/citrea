use demo_stf::genesis_config::GenesisPaths;
use sov_modules_stf_blueprint::kernels::basic::BasicKernelGenesisPaths;
use sov_stf_runner::RollupProverConfig;

use crate::evm::make_test_client;
// use sov_demo_rollup::initialize_logging;
use crate::test_helpers::{start_rollup, NodeMode};

/// Transaction with equal nonce to last tx should not be accepted by mempool.
#[should_panic = "Sequencer gave too many soft confirmations for a single block.: Block count per l1 block 10 should not be more than limiting number 10"]
#[tokio::test]
async fn too_many_l2_block_per_l1_block_should_panic() {
    // initialize_logging();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let _ = tokio::spawn(async {
        let seq_port = seq_port_rx.await.unwrap();
        let test_client = make_test_client(seq_port).await;
        let limiting_number = test_client.get_limiting_number().await;

        // limiting number should be 10
        // we use a low limiting number because mockda creates blocks every 5 seconds
        // and we want to test the panic in a reasonable time
        assert_eq!(limiting_number, 10);

        // create 2*limiting_number + 1 blocks so it has to give error
        for _ in 0..2 * limiting_number + 1 {
            let _response = test_client.spam_publish_batch_request().await;
        }
    });

    start_rollup(
        seq_port_tx,
        GenesisPaths::from_dir("../test-data/genesis/integration-tests-low-limiting-number"),
        BasicKernelGenesisPaths {
            chain_state:
                "../test-data/genesis/integration-tests-low-limiting-number/chain_state.json"
                    .into(),
        },
        RollupProverConfig::Execute,
        NodeMode::SequencerNode,
        None,
    )
    .await;
}
