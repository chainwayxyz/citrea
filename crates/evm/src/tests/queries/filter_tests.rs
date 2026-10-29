use alloy_eips::BlockNumberOrTag;
use alloy_rpc_types::{Filter, FilterChanges};
use reth_tasks::TaskManager;
use rstest::rstest;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module};
use sov_rollup_interface::spec::SpecId;

use super::init_evm;
use crate::call::CallMessage;
use crate::tests::get_test_seq_pub_key;
use crate::tests::utils::publish_event_message;
use crate::{CitreaFilter, FilterKind};

type C = DefaultContext;

#[rstest]
#[case::default_range(None, None)]
#[case::latest(Some(BlockNumberOrTag::Latest), None)]
#[case::historical_from_block(Some(BlockNumberOrTag::Number(1)), None)]
#[case::bounded_to_block(None, Some(6))]
#[tokio::test(flavor = "multi_thread")]
async fn filter_changes_returns_all_unpolled_logs(
    #[case] from_block: Option<BlockNumberOrTag>,
    #[case] to_block: Option<u64>,
) {
    let (mut evm, mut working_set, _, signer, first_height, _ledger_db) =
        init_evm(SpecId::latest());
    assert_eq!(first_height, 4);
    let contract_addr = signer.address().create(0);
    let task_manager = TaskManager::current();
    let filters = CitreaFilter::new(task_manager.executor(), None);
    let mut filter = Filter::default().address(contract_addr);
    if let Some(from) = from_block {
        filter = filter.from_block(from);
    }
    if let Some(to) = to_block {
        filter = filter.to_block(to);
    }
    let id = filters
        .install_filter(&mut working_set, &evm, FilterKind::Log(Box::new(filter)))
        .await
        .unwrap();

    // Produce five blocks before polling, then two more before the next poll.
    for height in first_height..=10 {
        let info = HookL2BlockInfo {
            l2_height: height,
            pre_state_root: [height as u8; 32],
            current_spec: SpecId::latest(),
            sequencer_pub_key: get_test_seq_pub_key(),
            l1_fee_rate: 1,
            timestamp: 24,
        };
        evm.begin_l2_block_hook(&info, &mut working_set);
        let context = C::new(generate_address::<C>("sender"), height, SpecId::latest(), 1);
        evm.call(
            CallMessage {
                txs: vec![publish_event_message(
                    contract_addr,
                    &signer,
                    9 + height - first_height,
                    format!("block {height}"),
                )],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
        evm.end_l2_block_hook(&info, &mut working_set);
        evm.finalize_hook(&[height as u8 + 1; 32], &mut working_set.accessory_state());

        if height != 8 && height != 10 {
            continue;
        }

        let from = if height == 8 {
            if matches!(from_block, Some(BlockNumberOrTag::Number(1))) {
                1
            } else {
                first_height - 1
            }
        } else {
            9
        };
        let to = to_block.unwrap_or(height).min(height);
        let expected = if from <= to {
            evm.eth_get_logs(
                Filter::default()
                    .address(contract_addr)
                    .from_block(from)
                    .to_block(to),
                &mut working_set,
            )
            .unwrap()
        } else {
            Vec::new()
        };
        let expected_count = match (height, from_block, to_block) {
            (8, Some(BlockNumberOrTag::Number(1)), _) => 22,
            (8, _, Some(6)) => 6,
            (8, _, _) => 10,
            (10, _, Some(6)) => 0,
            (10, _, _) => 4,
            _ => unreachable!(),
        };
        assert_eq!(expected.len(), expected_count);
        let changes = filters
            .filter_changes(&mut working_set, &evm, id.clone())
            .await
            .unwrap();
        assert_eq!(changes.as_logs().unwrap_or_default(), expected.as_slice());

        // Polling again without advancing the head must not replay logs.
        assert!(matches!(
            filters
                .filter_changes(&mut working_set, &evm, id.clone())
                .await
                .unwrap(),
            FilterChanges::Empty
        ));
    }
}
