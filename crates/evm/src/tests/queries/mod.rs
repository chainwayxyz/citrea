mod basic_queries;
mod estimate_gas_tests;
mod evm_call_tests;
mod log_tests;

use std::str::FromStr;

use reth_primitives::{address, Address, Bytes};
use revm::primitives::{KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, Spec, WorkingSet};
use sov_prover_storage_manager::SnapshotManager;
use sov_rollup_interface::spec::SpecId as SovSpecId;
use sov_state::ProverStorage;

use crate::call::CallMessage;
use crate::smart_contracts::{
    CallerContract, LogsContract, SimplePayableContract, SimpleStorageContract,
};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{
    commit, config_push_contracts, create_contract_transaction, get_evm_with_storage,
    publish_event_message, set_arg_message,
};
use crate::{AccountData, Evm, EvmConfig, RlpEvmTransaction};

type C = DefaultContext;
type Storage = ProverStorage<SnapshotManager>;

/// Creates evm instance with 4 blocks (including genesis)
/// Block 1 has 3 transactions
/// Block 2 has 4 transactions
/// Block 3 has 2 transactions
fn init_evm() -> (
    Evm<C>,
    WorkingSet<<C as Spec>::Storage>,
    Storage,
    TestSigner,
    u64,
) {
    let dev_signer: TestSigner = TestSigner::new_random();

    let mut config = EvmConfig {
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
        ..Default::default()
    };
    config_push_contracts(&mut config, None);
    let (mut evm, mut working_set, prover_storage) = get_evm_with_storage(&config);

    let l1_fee_rate = 1;
    let mut l2_height = 1;

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

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 24,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);

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

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());
    l2_height += 1;

    let mut working_set = WorkingSet::new(prover_storage.clone());

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [8u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [99u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 24,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);

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

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[100u8; 32].into(), &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());
    l2_height += 1;

    let mut working_set = WorkingSet::new(prover_storage.clone());

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [10u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [100u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 24,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);

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

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[101u8; 32].into(), &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());
    l2_height += 1;

    let working_set = WorkingSet::new(prover_storage.clone());

    (evm, working_set, prover_storage, dev_signer, l2_height)
}

pub fn init_evm_single_block() -> (Evm<C>, WorkingSet<<C as Spec>::Storage>, TestSigner) {
    let dev_signer: TestSigner = TestSigner::new_random();

    let mut config = EvmConfig {
        data: vec![
            AccountData {
                address: dev_signer.address(),
                balance: U256::from_str("100000000000000000000").unwrap(), // Setting initial balance
                code_hash: KECCAK_EMPTY,
                code: Bytes::default(),
                nonce: 0,
                storage: Default::default(),
            },
            AccountData {
                address: address!("0000000000000000000000000000000000000000"),
                balance: U256::from_str("100000000000000000000").unwrap(), // Setting initial balance
                code_hash: KECCAK_EMPTY,
                code: Bytes::default(),
                nonce: 0,
                storage: Default::default(),
            },
        ],
        ..Default::default()
    };
    config_push_contracts(&mut config, None);
    let (mut evm, mut working_set, prover_storage) = get_evm_with_storage(&config);

    // let contract_addr: Address = Address::from_slice(
    //     hex::decode("819c5497b157177315e1204f52e588b393771719")
    //         .unwrap()
    //         .as_slice(),
    // );

    let l1_fee_rate = 1;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height: 1,
        da_slot_hash: [1u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [0u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    let simple_payable_contract_tx =
        create_contract_transaction(&dev_signer, 0, SimplePayableContract::default());

    let sender_address = generate_address::<C>("sender");

    let context = C::new(sender_address, 1, SovSpecId::Genesis, l1_fee_rate);

    evm.call(
        CallMessage {
            txs: vec![simple_payable_contract_tx],
        },
        &context,
        &mut working_set,
    )
    .unwrap();

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[2u8; 32].into(), &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    let working_set = WorkingSet::new(prover_storage);

    (evm, working_set, dev_signer)
}

pub fn init_evm_with_caller_contract() -> (Evm<C>, WorkingSet<<C as Spec>::Storage>, TestSigner, u64)
{
    let dev_signer: TestSigner = TestSigner::new_random();

    let mut config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: U256::from_str("100000000000000000000").unwrap(), // Setting initial balance
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        ..Default::default()
    };
    config_push_contracts(&mut config, None);
    let (mut evm, mut working_set, prover_storage) = get_evm_with_storage(&config);

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

    let l1_fee_rate = 1;
    let mut l2_height = 1;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [1u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [0u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);

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

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[2u8; 32].into(), &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());
    l2_height += 1;

    let mut working_set = WorkingSet::new(prover_storage.clone());

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [2u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [2u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);

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

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[3u8; 32].into(), &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());
    l2_height += 1;

    let working_set = WorkingSet::new(prover_storage);

    (evm, working_set, dev_signer, l2_height)
}
