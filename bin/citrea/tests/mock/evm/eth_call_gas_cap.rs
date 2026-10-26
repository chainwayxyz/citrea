use std::time::Duration;

use alloy_primitives::{Address, Bytes, U256};
use alloy_rpc_types::state::{AccountOverride, StateOverride};
use alloy_rpc_types::{BlockId, BlockNumberOrTag, BlockOverrides, TransactionRequest};
use citrea_common::SequencerConfig;
use citrea_stf::genesis_config::GenesisPaths;

use super::init_test_rollup;
use crate::common::helpers::{
    create_default_rollup_config, start_rollup, tempdir_with_children, wait_for_l2_block, NodeMode,
};
use crate::common::{TEST_DATA_GENESIS_PATH, TEST_SEND_NO_COMMITMENT_MAX_L2_BLOCKS_PER_COMMITMENT};

#[tokio::test(flavor = "multi_thread")]
async fn rpc_gas_caps_are_isolated_between_servers() -> anyhow::Result<()> {
    let storage_dir = tempdir_with_children(&[
        "DA-0", "node-0", "DA-1", "node-1", "DA-2", "node-2", "DA-3", "node-3",
    ]);
    let mut nodes = Vec::new();
    for (index, gas_cap) in [30_000_000, 100_000_000, 0, u64::MAX]
        .into_iter()
        .enumerate()
    {
        let da_db_dir = storage_dir.path().join(format!("DA-{index}"));
        let sequencer_db_dir = storage_dir.path().join(format!("node-{index}"));
        let (port_tx, port_rx) = tokio::sync::oneshot::channel();
        let mut rollup_config = create_default_rollup_config(
            true,
            &sequencer_db_dir,
            &da_db_dir,
            NodeMode::SequencerNode,
            None,
        );
        rollup_config.rpc.gas_cap = gas_cap;
        let task_manager = start_rollup(
            port_tx,
            GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
            None,
            None,
            rollup_config,
            Some(SequencerConfig {
                max_l2_blocks_per_commitment: TEST_SEND_NO_COMMITMENT_MAX_L2_BLOCKS_PER_COMMITMENT,
                ..Default::default()
            }),
            None,
            false,
        )
        .await;
        let client = init_test_rollup(port_rx.await?).await;
        client.send_publish_batch_request().await;
        wait_for_l2_block(&client, 1, Some(Duration::from_secs(60))).await;
        let block = client
            .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
            .await;
        // The gas a call may actually burn: the configured cap clamped to the enforced maximum, or
        // the block gas limit when the cap is 0 ("keep the block gas limit").
        let effective_cap = if gas_cap == 0 {
            block.header.gas_limit
        } else {
            gas_cap.min(citrea_evm::RPC_DEFAULT_GAS_CAP)
        };
        nodes.push((task_manager, client, effective_cap));
    }

    // PUSH1 1, PUSH4 0x00600000 (6 MiB), MSTORE, STOP: expanding EVM memory to ~6 MiB costs ~76M
    // gas. Each server must run this only if its own effective cap covers it, and reject it for
    // lack of gas otherwise - proving the cap each one enforces comes from its own config alone.
    const HEAVY_CALL_GAS: u64 = 76_000_000;
    let heavy = Address::from([0xCC; 20]);
    let mut state_override = StateOverride::default();
    state_override.insert(
        heavy,
        AccountOverride {
            code: Some(Bytes::from_static(&[
                0x60, 0x01, 0x63, 0x00, 0x60, 0x00, 0x00, 0x52, 0x00,
            ])),
            ..Default::default()
        },
    );
    let checks = nodes.iter().map(|(_, client, effective_cap)| {
        let state_override = &state_override;
        async move {
            // Ask for u64::MAX request gas so only the server's own cap can bound the call.
            let request = TransactionRequest {
                from: Some(client.from_addr),
                gas: Some(u64::MAX),
                ..TransactionRequest::default().to(heavy)
            };
            let result = client
                .eth_call_result(
                    request,
                    Some(BlockId::Number(BlockNumberOrTag::Latest)),
                    Some(state_override.clone()),
                    None,
                )
                .await;
            if *effective_cap >= HEAVY_CALL_GAS {
                assert!(
                    result.is_ok(),
                    "a ~76M gas call must succeed under an effective cap of {effective_cap}"
                );
            } else {
                let err = result
                    .expect_err("a ~76M gas call must be rejected under an effective cap below it");
                assert!(
                    err.to_string().to_lowercase().contains("gas"),
                    "expected an out-of-gas error under cap {effective_cap}, got: {err}"
                );
            }
            Ok::<_, anyhow::Error>(())
        }
    });
    futures::future::try_join_all(checks).await?;
    for (task_manager, _, _) in nodes {
        task_manager.graceful_shutdown();
    }
    Ok(())
}

/// An `eth_call` whose contract expands EVM memory to a 256 GiB offset must be rejected out of gas
/// by the RPC gas cap instead of allocating 256 GiB. This exercises the real RPC path end to end:
/// neither a `u64::MAX` request gas nor a block override raising the block gas limit to `u64::MAX`
/// can lift the cap, and the node keeps serving afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn eth_call_with_256gib_memory_offset_is_rejected() -> Result<(), anyhow::Error> {
    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig {
        max_l2_blocks_per_commitment: TEST_SEND_NO_COMMITMENT_MAX_L2_BLOCKS_PER_COMMITMENT,
        ..Default::default()
    };

    let rollup_task = start_rollup(
        port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        Some(sequencer_config),
        None,
        false,
    )
    .await;

    let port = port_rx.await.unwrap();
    let client = init_test_rollup(port).await;

    // Produce a block so `latest` refers to a real EVM block.
    client.send_publish_batch_request().await;
    wait_for_l2_block(&client, 1, Some(Duration::from_secs(60))).await;

    // PUSH1 1, PUSH5 0x4000000000 (256 GiB), MSTORE, STOP. The MSTORE forces EVM memory to expand
    // to a 256 GiB offset, whose quadratic expansion cost dwarfs any block gas limit and the RPC
    // gas cap; revm charges that cost before allocating, so the call must be rejected for lack of
    // gas rather than allocate 256 GiB.
    let expander = Address::from([0xBB; 20]);
    let expander_code = Bytes::from(vec![
        0x60, 0x01, 0x64, 0x40, 0x00, 0x00, 0x00, 0x00, 0x52, 0x00,
    ]);
    let mut state_override = StateOverride::default();
    state_override.insert(
        expander,
        AccountOverride {
            code: Some(expander_code),
            ..Default::default()
        },
    );

    let request = || {
        TransactionRequest::default()
            .to(expander)
            .gas_limit(u64::MAX)
    };

    // Even asking for u64::MAX request gas, the call is capped and runs out of gas.
    let capped = client
        .eth_call_result(
            request(),
            Some(BlockId::Number(BlockNumberOrTag::Latest)),
            Some(state_override.clone()),
            None,
        )
        .await;
    let err = capped.expect_err("a 256 GiB memory expansion must be rejected out of gas");
    assert!(
        err.to_string().to_lowercase().contains("gas"),
        "expected an out-of-gas error, got: {err}"
    );

    // A block override raising the block gas limit to u64::MAX cannot lift the cap either.
    let with_override = client
        .eth_call_result(
            request(),
            Some(BlockId::Number(BlockNumberOrTag::Latest)),
            Some(state_override),
            Some(BlockOverrides {
                gas_limit: Some(u64::MAX),
                ..Default::default()
            }),
        )
        .await;
    let err = with_override
        .expect_err("a block override must not lift the gas cap to allow the 256 GiB call");
    assert!(
        err.to_string().to_lowercase().contains("gas"),
        "expected an out-of-gas error, got: {err}"
    );

    // The node survived both attempts and still serves requests.
    assert!(client.eth_block_number().await >= 1);

    rollup_task.graceful_shutdown();
    Ok(())
}

/// The RPC gas cap bounds how much gas an `eth_call` may burn, but it must not leak into the block
/// environment the call runs in: a contract reading the `GASLIMIT` opcode must still see the real
/// block gas limit, not the cap. Asking for `u64::MAX` request gas (which the cap clamps down) must
/// not change the value `GASLIMIT` reports.
#[tokio::test(flavor = "multi_thread")]
async fn eth_call_gaslimit_reports_the_block_gas_limit() -> Result<(), anyhow::Error> {
    let storage_dir = tempdir_with_children(&["DA", "sequencer"]);
    let da_db_dir = storage_dir.path().join("DA").to_path_buf();
    let sequencer_db_dir = storage_dir.path().join("sequencer").to_path_buf();

    let (port_tx, port_rx) = tokio::sync::oneshot::channel();

    let rollup_config = create_default_rollup_config(
        true,
        &sequencer_db_dir,
        &da_db_dir,
        NodeMode::SequencerNode,
        None,
    );
    let sequencer_config = SequencerConfig {
        max_l2_blocks_per_commitment: TEST_SEND_NO_COMMITMENT_MAX_L2_BLOCKS_PER_COMMITMENT,
        ..Default::default()
    };

    let rollup_task = start_rollup(
        port_tx,
        GenesisPaths::from_dir(TEST_DATA_GENESIS_PATH),
        None,
        None,
        rollup_config,
        Some(sequencer_config),
        None,
        false,
    )
    .await;

    let port = port_rx.await.unwrap();
    let client = init_test_rollup(port).await;

    client.send_publish_batch_request().await;
    wait_for_l2_block(&client, 1, Some(Duration::from_secs(60))).await;

    let block = client
        .eth_get_block_by_number(Some(BlockNumberOrTag::Latest))
        .await;
    let block_gas_limit = U256::from(block.header.gas_limit);
    // The block gas limit of the test genesis differs from the RPC gas cap, so the two are
    // distinguishable - otherwise this test would prove nothing.
    assert_ne!(block_gas_limit, U256::from(citrea_evm::RPC_DEFAULT_GAS_CAP));

    // GASLIMIT; PUSH1 0x00; MSTORE; PUSH1 0x20; PUSH1 0x00; RETURN - returns the GASLIMIT opcode's
    // value as a 32 byte word.
    let gaslimit = Address::from([0x6a; 20]);
    let mut state_override = StateOverride::default();
    state_override.insert(
        gaslimit,
        AccountOverride {
            code: Some(Bytes::from_static(&[
                0x45, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
            ])),
            ..Default::default()
        },
    );

    // u64::MAX request gas is clamped by the cap, which must not disturb the block environment.
    let request = TransactionRequest {
        from: Some(client.from_addr),
        gas: Some(u64::MAX),
        ..TransactionRequest::default().to(gaslimit)
    };
    let ret = client
        .eth_call_result(
            request,
            Some(BlockId::Number(BlockNumberOrTag::Latest)),
            Some(state_override),
            None,
        )
        .await?;
    let reported = U256::from_be_slice(ret.as_ref());
    assert_eq!(
        reported, block_gas_limit,
        "GASLIMIT must report the block gas limit {block_gas_limit}, got {reported}"
    );

    rollup_task.graceful_shutdown();
    Ok(())
}
