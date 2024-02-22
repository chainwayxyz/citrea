use std::time::Duration;

use borsh::BorshDeserialize;
use citrea_stf::genesis_config::GenesisPaths;
use log::debug;
use reth_rpc_types::BlockNumberOrTag;
use sov_mock_da::{MockAddress, MockDaService};
use sov_modules_api::BlobReaderTrait;
use sov_modules_stf_blueprint::kernels::basic::BasicKernelGenesisPaths;
use sov_rollup_interface::da::DaData;
use sov_rollup_interface::services::da::DaService;
use sov_stf_runner::RollupProverConfig;
use tokio::time::sleep;
use tracing::info;

use crate::evm::make_test_client;
use crate::test_helpers::{start_rollup, NodeMode};

#[tokio::test]
async fn sequencer_sends_commitments_to_da_layer() {
    sov_demo_rollup::initialize_logging();

    let (seq_port_tx, seq_port_rx) = tokio::sync::oneshot::channel();

    let seq_task = tokio::spawn(async {
        start_rollup(
            seq_port_tx,
            GenesisPaths::from_dir("../test-data/genesis/integration-tests"),
            BasicKernelGenesisPaths {
                chain_state:
                    "../test-data/genesis/integration-tests-low-limiting-number/chain_state.json"
                        .into(),
            },
            RollupProverConfig::Execute,
            NodeMode::SequencerNode,
            None,
            4,
        )
        .await;
    });

    let seq_port = seq_port_rx.await.unwrap();
    let test_client = make_test_client(seq_port).await;
    let da_service = MockDaService::new(MockAddress::from([0; 32]));

    // publish 3 soft confirmations, no commitment should be sent
    for _ in 0..3 {
        test_client.send_publish_batch_request().await;
        sleep(Duration::from_secs(3)).await; // 3 * 3 = 9 seconds, we also guarantee that a new L1 block is published
    }

    let mut height = 1;
    let last_finalized = da_service.get_head_block_header().await.unwrap().height;

    // look over all available da_blocks and check that no commitment was sent
    while height <= last_finalized {
        let block = da_service.get_block_at(height).await.unwrap();
        // let block = block.unwrap();

        let mut blobs = da_service.extract_relevant_blobs(&block);

        for mut blob in blobs.drain(0..) {
            let data = blob.full_data();

            assert_eq!(data, &[1]); // empty blocks in mock da have blobs [1]
        }

        height += 1;
    }

    sleep(Duration::from_secs(5)).await; // wait 5 secs so that new L1 block will be published

    test_client.send_publish_batch_request().await;
    sleep(Duration::from_secs(5)).await; // wait 5 secs so that new L1 block will be published
    test_client.send_publish_batch_request().await;

    let last_finalized_height = da_service.get_head_block_header().await.unwrap().height;
    let block = da_service
        .get_block_at(last_finalized_height)
        .await
        .unwrap();

    let mut blobs = da_service.extract_relevant_blobs(&block);

    assert_eq!(blobs.len(), 1);

    let mut blob = blobs.pop().unwrap();

    let data = blob.full_data();

    debug!("Len: {}", data.len());

    debug!("deserialized: {:?}", DaData::try_from_slice(data));

    seq_task.abort();
}
