use sov_accounts::Response;
use sov_data_generators::bank_data::{get_default_private_key, get_default_token_address};
use sov_data_generators::new_test_blob_from_batch;
use sov_mock_da::{MockAddress, MockBlock, MockDaSpec, MOCK_SEQUENCER_DA_ADDRESS};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::{PrivateKey, WorkingSet};
use sov_modules_stf_blueprint::{Batch, StfBlueprint, TxEffect};
use sov_rollup_interface::services::da::SlotData;
use sov_rollup_interface::stf::StateTransitionFunction;
use sov_rollup_interface::storage::HierarchicalStorageManager;

use super::{create_storage_manager_for_tests, get_genesis_config_for_tests, RuntimeTest};
use crate::runtime::Runtime;
use crate::tests::da_simulation::{
    simulate_da_with_bad_nonce, simulate_da_with_bad_serialization, simulate_da_with_bad_sig,
    simulate_da_with_revert_msg,
};
use crate::tests::StfBlueprintTest;

// Assume there was proper address and we converted it to bytes already.
const SEQUENCER_DA_ADDRESS: [u8; 32] = [1; 32];

#[test]
fn test_tx_revert() {
    // Test checks:
    //  - Batch is successfully applied even with incorrect txs
    //  - Nonce for bad transactions has increased

    let tempdir = tempfile::tempdir().unwrap();

    let config = get_genesis_config_for_tests();
    let sequencer_rollup_address = config.runtime.sequencer_registry.seq_rollup_address;

    let genesis_block = MockBlock::default();
    let block_1 = genesis_block.next_mock();

    let storage = {
        let mut storage_manager = create_storage_manager_for_tests(tempdir.path());
        let stf: StfBlueprintTest = StfBlueprint::new();

        let (genesis_root, storage) = stf.init_chain(
            storage_manager
                .create_storage_on(genesis_block.header())
                .unwrap(),
            config,
        );
        storage_manager
            .save_change_set(genesis_block.header(), storage)
            .unwrap();

        let txs = simulate_da_with_revert_msg();
        let blob = new_test_blob_from_batch(Batch { txs }, &MOCK_SEQUENCER_DA_ADDRESS, [0; 32]);
        let mut blobs = [blob];

        let storage = storage_manager.create_storage_on(block_1.header()).unwrap();
        let apply_block_result = stf.apply_slot(
            &genesis_root,
            storage,
            Default::default(),
            &block_1.header,
            &block_1.validity_cond,
            &mut blobs,
        );

        assert_eq!(1, apply_block_result.batch_receipts.len());
        // let apply_blob_outcome = apply_block_result.batch_receipts[0].clone();

        // assert_eq!(
        //     SequencerOutcome::Rewarded(0),
        //     apply_blob_outcome.inner,
        //     "Unexpected outcome: Batch execution should have succeeded",
        // );

        let txn_receipts = apply_block_result.batch_receipts[0].tx_receipts.clone();
        // 3 transactions
        // create 1000 tokens
        // transfer 15 tokens
        // transfer 5000 tokens // this should be reverted
        assert_eq!(txn_receipts[0].receipt, TxEffect::Successful);
        assert_eq!(txn_receipts[1].receipt, TxEffect::Successful);
        assert_eq!(txn_receipts[2].receipt, TxEffect::Reverted);

        apply_block_result.change_set
    };

    // Checks on storage after execution
    {
        let runtime = &mut Runtime::<DefaultContext, MockDaSpec>::default();
        let mut working_set = WorkingSet::new(storage);
        let resp = runtime
            .bank
            .balance_of(
                get_default_private_key().default_address(),
                get_default_token_address(),
                &mut working_set,
            )
            .unwrap();

        assert_eq!(resp.amount, Some(985));

        let resp = runtime
            .sequencer_registry
            .sequencer_address(
                MockAddress::from(MOCK_SEQUENCER_DA_ADDRESS),
                &mut working_set,
            )
            .unwrap();
        // Sequencer is not excluded from list of allowed!
        assert_eq!(Some(sequencer_rollup_address), resp.address);

        let nonce = match runtime
            .accounts
            .get_account(get_default_private_key().pub_key(), &mut working_set)
            .unwrap()
        {
            Response::AccountExists { nonce, .. } => nonce,
            Response::AccountEmpty => 0,
        };

        // with 3 transactions, the final nonce should be 3
        // 0 -> 1
        // 1 -> 2
        // 2 -> 3
        // minter account should have its nonce increased for 3 transactions
        assert_eq!(3, nonce);
    }
}

#[test]
fn test_tx_bad_signature() {
    let tempdir = tempfile::tempdir().unwrap();
    let path = tempdir.path();

    let config = get_genesis_config_for_tests();

    let genesis_block = MockBlock::default();
    let block_1 = genesis_block.next_mock();
    let storage = {
        let mut storage_manager = create_storage_manager_for_tests(path);
        let stf: StfBlueprintTest = StfBlueprint::new();
        let (genesis_root, storage) = stf.init_chain(
            storage_manager
                .create_storage_on(genesis_block.header())
                .unwrap(),
            config,
        );
        storage_manager
            .save_change_set(genesis_block.header(), storage)
            .unwrap();

        let txs = simulate_da_with_bad_sig();

        let blob = new_test_blob_from_batch(Batch { txs }, &MOCK_SEQUENCER_DA_ADDRESS, [0; 32]);
        // let blob_sender = blob.sender();
        let mut blobs = [blob];

        let storage = storage_manager.create_storage_on(block_1.header()).unwrap();
        let apply_block_result = stf.apply_slot(
            &genesis_root,
            storage,
            Default::default(),
            &block_1.header,
            &block_1.validity_cond,
            &mut blobs,
        );

        assert_eq!(1, apply_block_result.batch_receipts.len());
        // let apply_blob_outcome = apply_block_result.batch_receipts[0].clone();

        // assert_eq!(
        //     SequencerOutcome::Slashed{
        //         reason:SlashingReason::StatelessVerificationFailed,
        //         sequencer_da_address: blob_sender,
        //     },
        //     apply_blob_outcome.inner,
        //     "Unexpected outcome: Stateless verification should have failed due to invalid signature"
        // );

        // The batch receipt contains no events.
        // assert!(!has_tx_events(&apply_blob_outcome));
        apply_block_result.change_set
    };

    {
        let runtime = &mut Runtime::<DefaultContext, MockDaSpec>::default();
        let mut working_set = WorkingSet::new(storage);
        let nonce = match runtime
            .accounts
            .get_account(get_default_private_key().pub_key(), &mut working_set)
            .unwrap()
        {
            Response::AccountExists { nonce, .. } => nonce,
            Response::AccountEmpty => 0,
        };
        assert_eq!(0, nonce);
    }
}

#[test]
fn test_tx_bad_nonce() {
    let tempdir = tempfile::tempdir().unwrap();
    let path = tempdir.path();

    let config = get_genesis_config_for_tests();
    let genesis_block = MockBlock::default();
    let block_1 = genesis_block.next_mock();
    {
        let mut storage_manager = create_storage_manager_for_tests(path);
        let stf: StfBlueprintTest = StfBlueprint::new();
        let (genesis_root, storage) = stf.init_chain(
            storage_manager
                .create_storage_on(genesis_block.header())
                .unwrap(),
            config,
        );
        storage_manager
            .save_change_set(genesis_block.header(), storage)
            .unwrap();
        let txs = simulate_da_with_bad_nonce();

        let blob = new_test_blob_from_batch(Batch { txs }, &MOCK_SEQUENCER_DA_ADDRESS, [0; 32]);
        let mut blobs = [blob];

        let storage = storage_manager.create_storage_on(block_1.header()).unwrap();
        let apply_block_result = stf.apply_slot(
            &genesis_root,
            storage,
            Default::default(),
            &block_1.header,
            &block_1.validity_cond,
            &mut blobs,
        );

        assert_eq!(1, apply_block_result.batch_receipts.len());
        let tx_receipts = apply_block_result.batch_receipts[0].tx_receipts.clone();
        // Bad nonce means that the transaction has to be reverted
        assert_eq!(tx_receipts[0].receipt, TxEffect::Reverted);

        // We don't expect the sequencer to be slashed for a bad nonce
        // The reason for this is that in cases such as based sequencing, the sequencer can
        // still post under the assumption that the nonce is valid (It doesn't know other sequencers
        // are also doing this) so it needs to be rewarded.
        // We're asserting that here to track if the logic changes
        // assert_eq!(
        //     apply_block_result.batch_receipts[0].inner,
        //     SequencerOutcome::Rewarded(0)
        // );
    }
}

#[test]
fn test_tx_bad_serialization() {
    let tempdir = tempfile::tempdir().unwrap();
    let path = tempdir.path();

    let config = get_genesis_config_for_tests();
    let sequencer_rollup_address = config.runtime.sequencer_registry.seq_rollup_address;

    let genesis_block = MockBlock::default();
    let block_1 = genesis_block.next_mock();
    let mut storage_manager = create_storage_manager_for_tests(path);

    let (genesis_root, sequencer_balance_before) = {
        let stf: StfBlueprintTest = StfBlueprint::new();

        let (genesis_root, storage) = stf.init_chain(
            storage_manager
                .create_storage_on(genesis_block.header())
                .unwrap(),
            config,
        );

        let balance = {
            let runtime: RuntimeTest = Runtime::default();
            let mut working_set = WorkingSet::new(storage.clone());

            let coins = runtime
                .sequencer_registry
                .get_coins_to_lock(&mut working_set)
                .unwrap();

            runtime
                .bank
                .get_balance_of(
                    sequencer_rollup_address,
                    coins.token_address,
                    &mut working_set,
                )
                .unwrap()
        };
        storage_manager
            .save_change_set(genesis_block.header(), storage)
            .unwrap();
        (genesis_root, balance)
    };

    let storage = {
        let stf: StfBlueprintTest = StfBlueprint::new();

        let txs = simulate_da_with_bad_serialization();
        let blob = new_test_blob_from_batch(Batch { txs }, &MOCK_SEQUENCER_DA_ADDRESS, [0; 32]);
        // let blob_sender = blob.sender();
        let mut blobs = [blob];

        let storage = storage_manager.create_storage_on(block_1.header()).unwrap();
        let apply_block_result = stf.apply_slot(
            &genesis_root,
            storage,
            Default::default(),
            &block_1.header,
            &block_1.validity_cond,
            &mut blobs,
        );

        assert_eq!(1, apply_block_result.batch_receipts.len());
        // let apply_blob_outcome = apply_block_result.batch_receipts[0].clone();

        // assert_eq!(
        //     SequencerOutcome::Slashed {
        //         reason: SlashingReason::InvalidTransactionEncoding ,
        //         sequencer_da_address: blob_sender,
        //     },
        //     apply_blob_outcome.inner,
        //     "Unexpected outcome: Stateless verification should have failed due to invalid signature"
        // );

        // The batch receipt contains no events.
        // assert!(!has_tx_events(&apply_blob_outcome));
        apply_block_result.change_set
    };

    {
        let runtime = &mut Runtime::<DefaultContext, MockDaSpec>::default();
        let mut working_set = WorkingSet::new(storage);

        // Sequencer is not in the list of allowed sequencers

        let allowed_sequencer = runtime
            .sequencer_registry
            .sequencer_address(MockAddress::from(SEQUENCER_DA_ADDRESS), &mut working_set)
            .unwrap();
        assert!(allowed_sequencer.address.is_none());

        // Balance of sequencer is not increased
        let coins = runtime
            .sequencer_registry
            .get_coins_to_lock(&mut working_set)
            .unwrap();
        let sequencer_balance_after = runtime
            .bank
            .get_balance_of(
                sequencer_rollup_address,
                coins.token_address,
                &mut working_set,
            )
            .unwrap();
        assert_eq!(sequencer_balance_before, sequencer_balance_after);
    }
}
