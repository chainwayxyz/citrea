use helpers::*;
use sov_mock_da::{MockAddress, MockBlob};
use sov_modules_api::hooks::ApplyBlobHooks;
use sov_modules_api::WorkingSet;
use sov_prover_storage_manager::new_orphan_storage;
use sov_sequencer_registry::SequencerRegistry;

mod helpers;

#[test]
fn begin_blob_hook_known_sequencer() {
    let mut test_sequencer = create_test_sequencer();
    let tmpdir = tempfile::tempdir().unwrap();
    let working_set = &mut WorkingSet::new(new_orphan_storage(tmpdir.path()).unwrap());
    test_sequencer.genesis(working_set);

    let balance_after_genesis = {
        let resp = test_sequencer.query_balance_via_bank(working_set).unwrap();
        resp.amount.unwrap()
    };
    assert_eq!(INITIAL_BALANCE - LOCKED_AMOUNT, balance_after_genesis);

    let genesis_sequencer_da_address = MockAddress::from(GENESIS_SEQUENCER_DA_ADDRESS);

    let mut test_blob = MockBlob::new(Vec::new(), genesis_sequencer_da_address, [0_u8; 32]);

    test_sequencer
        .registry
        .begin_blob_hook(&mut test_blob, working_set)
        .unwrap();

    let resp = test_sequencer.query_balance_via_bank(working_set).unwrap();
    assert_eq!(balance_after_genesis, resp.amount.unwrap());
    let resp = test_sequencer
        .registry
        .sequencer_address(genesis_sequencer_da_address, working_set)
        .unwrap();
    assert!(resp.address.is_some());
}

#[test]
fn begin_blob_hook_unknown_sequencer() {
    let mut test_sequencer = create_test_sequencer();
    let tmpdir = tempfile::tempdir().unwrap();
    let working_set = &mut WorkingSet::new(new_orphan_storage(tmpdir.path()).unwrap());
    test_sequencer.genesis(working_set);

    let mut test_blob = MockBlob::new(
        Vec::new(),
        MockAddress::from(UNKNOWN_SEQUENCER_DA_ADDRESS),
        [0_u8; 32],
    );

    let result = test_sequencer
        .registry
        .begin_blob_hook(&mut test_blob, working_set);
    assert!(result.is_err());
    let expected_message = format!(
        "sender {} is not allowed to submit blobs",
        MockAddress::from(UNKNOWN_SEQUENCER_DA_ADDRESS)
    );
    let actual_message = result.err().unwrap().to_string();
    assert_eq!(expected_message, actual_message);
}

#[test]
fn end_blob_hook_success() {
    let mut test_sequencer = create_test_sequencer();
    let tmpdir = tempfile::tempdir().unwrap();
    let working_set = &mut WorkingSet::new(new_orphan_storage(tmpdir.path()).unwrap());
    test_sequencer.genesis(working_set);
    let balance_after_genesis = {
        let resp = test_sequencer.query_balance_via_bank(working_set).unwrap();
        resp.amount.unwrap()
    };
    assert_eq!(INITIAL_BALANCE - LOCKED_AMOUNT, balance_after_genesis);

    let genesis_sequencer_da_address = MockAddress::from(GENESIS_SEQUENCER_DA_ADDRESS);

    let mut test_blob = MockBlob::new(Vec::new(), genesis_sequencer_da_address, [0_u8; 32]);

    test_sequencer
        .registry
        .begin_blob_hook(&mut test_blob, working_set)
        .unwrap();

    <SequencerRegistry<C, Da> as ApplyBlobHooks<MockBlob>>::end_blob_hook(
        &test_sequencer.registry,
        working_set,
    )
    .unwrap();
    let resp = test_sequencer.query_balance_via_bank(working_set).unwrap();
    assert_eq!(balance_after_genesis, resp.amount.unwrap());
    let resp = test_sequencer
        .registry
        .sequencer_address(genesis_sequencer_da_address, working_set)
        .unwrap();
    assert!(resp.address.is_some());
}

#[test]
fn end_blob_hook_slash_unknown_sequencer() {
    let mut test_sequencer = create_test_sequencer();
    let tmpdir = tempfile::tempdir().unwrap();
    let working_set = &mut WorkingSet::new(new_orphan_storage(tmpdir.path()).unwrap());
    test_sequencer.genesis(working_set);

    let mut test_blob = MockBlob::new(
        Vec::new(),
        MockAddress::from(GENESIS_SEQUENCER_DA_ADDRESS),
        [0_u8; 32],
    );

    let sequencer_address = MockAddress::from(UNKNOWN_SEQUENCER_DA_ADDRESS);

    test_sequencer
        .registry
        .begin_blob_hook(&mut test_blob, working_set)
        .unwrap();

    let resp = test_sequencer
        .registry
        .sequencer_address(sequencer_address, working_set)
        .unwrap();
    assert!(resp.address.is_none());

    <SequencerRegistry<C, Da> as ApplyBlobHooks<MockBlob>>::end_blob_hook(
        &test_sequencer.registry,
        working_set,
    )
    .unwrap();

    let resp = test_sequencer
        .registry
        .sequencer_address(sequencer_address, working_set)
        .unwrap();
    assert!(resp.address.is_none());
}
