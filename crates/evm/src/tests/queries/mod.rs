mod basic_queries;
mod estimate_gas_tests;
mod evm_call_tests;
mod log_tests;

use std::str::FromStr;

use reth_primitives::{Address, Bytes};
use revm::primitives::{SpecId, KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, WorkingSet};
use sov_prover_storage_manager::{new_orphan_storage, SnapshotManager};
use sov_state::{DefaultStorageSpec, ProverStorage, Storage};

use crate::call::CallMessage;
use crate::smart_contracts::{
    CallerContract, LogsContract, SimplePayableContract, SimpleStorageContract,
};
use crate::tests::call_tests::{
    create_contract_transaction, publish_event_message, set_arg_message,
};
use crate::tests::genesis_tests::GENESIS_STATE_ROOT;
use crate::tests::test_signer::TestSigner;
use crate::{AccountData, Evm, EvmConfig, RlpEvmTransaction};

type C = DefaultContext;

/// Creates evm instance with 4 blocks (including genesis)
/// Block 1 has 3 transactions
/// Block 2 has 4 transactions
/// Block 3 has 2 transactions
fn init_evm() -> (Evm<C>, WorkingSet<C>, TestSigner) {
    let dev_signer: TestSigner = TestSigner::new_random();

    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: U256::from_str("100000000000000000000").unwrap(),
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        // SHANGAI instead of LATEST
        // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
        ..Default::default()
    };

    let (evm, mut working_set, prover_storage) = get_evm_with_storage(&config);

    let contract_addr: Address = Address::from_slice(
        hex::decode("819c5497b157177315e1204f52e588b393771719")
            .unwrap()
            .as_slice(),
    );

    let contract_addr2: Address = Address::from_slice(
        hex::decode("eeb03d20dae810f52111b853b31c8be6f30f4cd3")
            .unwrap()
            .as_slice(),
    );

    evm.begin_soft_confirmation_hook(
        [5u8; 32],
        1,
        [42u8; 32],
        &[10u8; 32],
        vec![],
        1,
        24,
        &mut working_set,
    );

    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(sender_address, sequencer_address, 1);

        let transactions: Vec<RlpEvmTransaction> = vec![
            create_contract_transaction(&dev_signer, 0, LogsContract::default()),
            publish_event_message(contract_addr, &dev_signer, 1, "hello".to_string()),
            publish_event_message(contract_addr, &dev_signer, 2, "hi".to_string()),
        ];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_soft_confirmation_hook(&mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    let mut working_set: WorkingSet<DefaultContext> = WorkingSet::new(prover_storage.clone());

    evm.begin_soft_confirmation_hook(
        [8u8; 32],
        1,
        [42u8; 32],
        &[99u8; 32],
        vec![],
        1,
        24,
        &mut working_set,
    );

    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(sender_address, sequencer_address, 1);

        let transactions: Vec<RlpEvmTransaction> = vec![
            publish_event_message(contract_addr, &dev_signer, 3, "hello2".to_string()),
            publish_event_message(contract_addr, &dev_signer, 4, "hi2".to_string()),
            publish_event_message(contract_addr, &dev_signer, 5, "hi3".to_string()),
            publish_event_message(contract_addr, &dev_signer, 6, "hi4".to_string()),
        ];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_soft_confirmation_hook(&mut working_set);
    evm.finalize_hook(&[100u8; 32].into(), &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    let mut working_set: WorkingSet<DefaultContext> = WorkingSet::new(prover_storage.clone());

    evm.begin_soft_confirmation_hook(
        [10u8; 32],
        1,
        [42u8; 32],
        &[100u8; 32],
        vec![],
        1,
        24,
        &mut working_set,
    );

    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(sender_address, sequencer_address, 1);

        let transactions: Vec<RlpEvmTransaction> = vec![
            create_contract_transaction(&dev_signer, 7, SimpleStorageContract::default()),
            set_arg_message(contract_addr2, &dev_signer, 8, 478),
        ];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_soft_confirmation_hook(&mut working_set);
    evm.finalize_hook(&[101u8; 32].into(), &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    let working_set: WorkingSet<DefaultContext> = WorkingSet::new(prover_storage.clone());

    (evm, working_set, dev_signer)
}

pub fn init_evm_single_block() -> (Evm<C>, WorkingSet<C>, TestSigner) {
    let dev_signer: TestSigner = TestSigner::new_random();

    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: U256::from_str("100000000000000000000").unwrap(), // Setting initial balance
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
        ..Default::default()
    };

    let (evm, mut working_set, prover_storage) = get_evm_with_storage(&config);

    // let contract_addr: Address = Address::from_slice(
    //     hex::decode("819c5497b157177315e1204f52e588b393771719")
    //         .unwrap()
    //         .as_slice(),
    // );

    evm.begin_soft_confirmation_hook(
        [1u8; 32],
        1,
        [42u8; 32],
        &[0u8; 32],
        vec![],
        1,
        0,
        &mut working_set,
    );

    let simple_payable_contract_tx =
        create_contract_transaction(&dev_signer, 0, SimplePayableContract::default());

    let sender_address = generate_address::<C>("sender");
    let sequencer_address = generate_address::<C>("sequencer");
    let context = C::new(sender_address, sequencer_address, 1);

    evm.call(
        CallMessage {
            txs: vec![simple_payable_contract_tx],
        },
        &context,
        &mut working_set,
    )
    .unwrap();

    evm.end_soft_confirmation_hook(&mut working_set);
    evm.finalize_hook(&[2u8; 32].into(), &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    let working_set: WorkingSet<DefaultContext> = WorkingSet::new(prover_storage);

    (evm, working_set, dev_signer)
}

pub fn init_evm_with_caller_contract() -> (Evm<C>, WorkingSet<C>, TestSigner) {
    let dev_signer: TestSigner = TestSigner::new_random();

    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: U256::from_str("100000000000000000000").unwrap(), // Setting initial balance
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
        ..Default::default()
    };

    let (evm, mut working_set, prover_storage) = get_evm_with_storage(&config);

    let contract_addr: Address = Address::from_slice(
        hex::decode("819c5497b157177315e1204f52e588b393771719")
            .unwrap()
            .as_slice(),
    );

    // Address of the caller contract
    // let contract_addr2: Address = Address::from_slice(
    //     hex::decode("5ccda3e6d071a059f00d4f3f25a1adc244eb5c93")
    //         .unwrap()
    //         .as_slice(),
    // );

    evm.begin_soft_confirmation_hook(
        [1u8; 32],
        1,
        [42u8; 32],
        &[0u8; 32],
        vec![],
        1,
        0,
        &mut working_set,
    );

    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(sender_address, sequencer_address, 1);

        let transactions: Vec<RlpEvmTransaction> = vec![
            create_contract_transaction(&dev_signer, 0, SimpleStorageContract::default()),
            set_arg_message(contract_addr, &dev_signer, 1, 7878),
        ];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_soft_confirmation_hook(&mut working_set);
    evm.finalize_hook(&[2u8; 32].into(), &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    let mut working_set: WorkingSet<DefaultContext> = WorkingSet::new(prover_storage.clone());

    evm.begin_soft_confirmation_hook(
        [2u8; 32],
        1,
        [42u8; 32],
        &[2u8; 32],
        vec![],
        1,
        0,
        &mut working_set,
    );

    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(sender_address, sequencer_address, 1);

        let transactions: Vec<RlpEvmTransaction> = vec![create_contract_transaction(
            &dev_signer,
            2,
            CallerContract::default(),
        )];

        evm.call(
            CallMessage { txs: transactions },
            &context,
            &mut working_set,
        )
        .unwrap();
    }

    evm.end_soft_confirmation_hook(&mut working_set);
    evm.finalize_hook(&[3u8; 32].into(), &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    let working_set: WorkingSet<DefaultContext> = WorkingSet::new(prover_storage);

    (evm, working_set, dev_signer)
}

fn get_evm_with_storage(
    config: &EvmConfig,
) -> (
    Evm<C>,
    WorkingSet<DefaultContext>,
    ProverStorage<DefaultStorageSpec, SnapshotManager>,
) {
    let tmpdir = tempfile::tempdir().unwrap();
    let prover_storage = new_orphan_storage(tmpdir.path()).unwrap();
    let mut working_set = WorkingSet::new(prover_storage.clone());
    let evm = Evm::<C>::default();
    evm.genesis(config, &mut working_set).unwrap();

    let mut genesis_state_root = [0u8; 32];
    genesis_state_root.copy_from_slice(GENESIS_STATE_ROOT.as_ref());

    evm.finalize_hook(
        &genesis_state_root.into(),
        &mut working_set.accessory_state(),
    );
    (evm, working_set, prover_storage)
}

pub(crate) fn commit(
    working_set: WorkingSet<DefaultContext>,
    storage: ProverStorage<DefaultStorageSpec, SnapshotManager>,
) -> [u8; 32] {
    // Save checkpoint
    let mut checkpoint = working_set.checkpoint();

    let (cache_log, witness) = checkpoint.freeze();

    let (root, authenticated_node_batch) = storage
        .compute_state_update(cache_log, &witness)
        .expect("jellyfish merkle tree update must succeed");

    let working_set = checkpoint.to_revertable();

    let accessory_log = working_set.checkpoint().freeze_non_provable();

    storage.commit(&authenticated_node_batch, &accessory_log);

    root.0
}
