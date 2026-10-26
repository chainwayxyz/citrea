mod basic_queries;
mod estimate_gas_override_tests;
mod estimate_gas_tests;
mod eth_call_tests;
mod log_tests;
mod pending_block_tests;
mod trace_call_tests;

use std::str::FromStr;

use alloy_primitives::{address, Bytes, TxKind};
use revm::primitives::{KECCAK_EMPTY, U256};
use sov_db::ledger_db::LedgerDB;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, Spec, WorkingSet};
use sov_rollup_interface::spec::SpecId as SovSpecId;
use sov_state::ProverStorage;

use super::get_test_seq_pub_key;
use crate::call::CallMessage;
use crate::smart_contracts::{
    CallerContract, LogsContract, SimplePayableContract, SimpleStorageContract,
};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{
    commit, create_contract_message_with_bytecode, create_contract_transaction,
    get_evm_with_storage, publish_event_message, set_arg_message,
};
use crate::{AccountData, Evm, EvmConfig, RlpEvmTransaction};

type C = DefaultContext;
type Storage = ProverStorage;

/// Creates evm instance with 4 blocks (including genesis)
/// Block 1 has 3 transactions
/// Block 2 has 4 transactions
/// Block 3 has 2 transactions
fn init_evm(
    spec_id: SovSpecId,
) -> (
    Evm<C>,
    WorkingSet<<C as Spec>::Storage>,
    Storage,
    TestSigner,
    u64, // l2_height
    LedgerDB,
) {
    let dev_signer: TestSigner = TestSigner::new_default();

    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: U256::from_str("100000000000000000000").unwrap(),
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        ..Default::default()
    };

    let (mut evm, mut working_set, prover_storage, ledger_db) = get_evm_with_storage(&config);

    let l1_fee_rate = 1;
    let mut l2_height = 1;

    let contract_addr = dev_signer.address().create(0);

    let contract_addr2 = dev_signer.address().create(7);

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: spec_id,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 24,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, spec_id, l1_fee_rate);

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

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());
    l2_height += 1;

    let mut working_set = WorkingSet::new(prover_storage.clone());

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [99u8; 32],
        current_spec: spec_id,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 24,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, spec_id, l1_fee_rate);

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

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[100u8; 32], &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());
    l2_height += 1;

    let mut working_set = WorkingSet::new(prover_storage.clone());

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [100u8; 32],
        current_spec: spec_id,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 24,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, spec_id, l1_fee_rate);

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

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[101u8; 32], &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());
    l2_height += 1;

    let working_set = WorkingSet::new(prover_storage.clone());
    (
        evm,
        working_set,
        prover_storage,
        dev_signer,
        l2_height,
        ledger_db,
    )
}

pub fn init_evm_single_block(
    spec_id: SovSpecId,
) -> (
    Evm<C>,
    WorkingSet<<C as Spec>::Storage>,
    TestSigner,
    LedgerDB,
) {
    let dev_signer: TestSigner = TestSigner::new_default();

    let config = EvmConfig {
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

    let (mut evm, mut working_set, prover_storage, ledger_db) = get_evm_with_storage(&config);

    // let contract_addr: Address = Address::from_slice(
    //     hex::decode("819c5497b157177315e1204f52e588b393771719")
    //         .unwrap()
    //         .as_slice(),
    // );

    let l1_fee_rate = 1;

    let l2_block_info = HookL2BlockInfo {
        l2_height: 1,
        pre_state_root: [0u8; 32],
        current_spec: spec_id,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    let simple_payable_contract_tx =
        create_contract_transaction(&dev_signer, 0, SimplePayableContract::default());

    let sender_address = generate_address::<C>("sender");

    let context = C::new(sender_address, 1, spec_id, l1_fee_rate);

    evm.call(
        CallMessage {
            txs: vec![simple_payable_contract_tx],
        },
        &context,
        &mut working_set,
    )
    .unwrap();

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[2u8; 32], &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    let working_set = WorkingSet::new(prover_storage);
    (evm, working_set, dev_signer, ledger_db)
}

/// Builds an evm with a single post-genesis block whose transactions are, in order:
///
/// 0. a deploy of a contract whose runtime is an unbounded `JUMPDEST; PUSH1 0x00; JUMP` loop,
/// 1. a call to that contract that burns its whole gas limit in the loop,
/// 2. a second such gas-burning call,
/// 3. a cheap value transfer that executes no bytecode.
///
/// It is used to check that tracing transaction 3 does not trace transactions 0-2: the two
/// gas-burning transactions each produce tens of megabytes of struct-log steps, so tracing them
/// against a small budget fails, but they must not be charged against the budget of a later
/// transaction that is only asking for its own trace.
///
/// Returns the storage rather than a working set: a failed trace still commits its prefix state,
/// so each trace request must run against its own fresh working set, exactly as the RPC layer does.
pub fn init_evm_prefix_regression_block(spec_id: SovSpecId) -> (Evm<C>, Storage, u64, LedgerDB) {
    let dev_signer: TestSigner = TestSigner::new_default();

    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: U256::from_str("100000000000000000000").unwrap(),
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        ..Default::default()
    };

    let (mut evm, working_set, prover_storage, ledger_db) = get_evm_with_storage(&config);

    // Commit genesis on its own so it is db version 1, exactly as a real node does. Tracing a
    // historical block resets state to the end of the previous block by archival version, and that
    // math assumes genesis is a separate version. Bundling genesis into the block's commit would
    // make the reset land on the block's own post-state instead of on genesis.
    commit(working_set, prover_storage.clone());
    let mut working_set = WorkingSet::new(prover_storage.clone());

    let l1_fee_rate = 1;
    let l2_block_info = HookL2BlockInfo {
        l2_height: 1,
        pre_state_root: [0u8; 32],
        current_spec: spec_id,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    // init code that returns the runtime `5b 60 00 56` (JUMPDEST; PUSH1 0x00; JUMP)
    let loop_deployer = vec![
        0x60, 0x04, 0x80, 0x60, 0x0b, 0x60, 0x00, 0x39, 0x60, 0x00,
        0xf3, // return runtime[0..4]
        0x5b, 0x60, 0x00, 0x56, // runtime: the loop
    ];
    let loop_contract = dev_signer.address().create(0);
    let sink = address!("0000000000000000000000000000000000000099");

    let transactions = vec![
        create_contract_message_with_bytecode(&dev_signer, 0, loop_deployer, None),
        dev_signer
            .sign_default_transaction(TxKind::Call(loop_contract), vec![], 1, 0)
            .unwrap(),
        dev_signer
            .sign_default_transaction(TxKind::Call(loop_contract), vec![], 2, 0)
            .unwrap(),
        dev_signer
            .sign_default_transaction(TxKind::Call(sink), vec![], 3, 1)
            .unwrap(),
    ];

    let sender_address = generate_address::<C>("sender");
    let context = C::new(sender_address, 1, spec_id, l1_fee_rate);
    evm.call(
        CallMessage { txs: transactions },
        &context,
        &mut working_set,
    )
    .unwrap();

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[2u8; 32], &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    let mut working_set = WorkingSet::new(prover_storage.clone());
    let block_number = evm
        .block_number(&mut working_set)
        .unwrap()
        .saturating_to::<u64>();

    (evm, prover_storage, block_number, ledger_db)
}

/// Builds a block whose transaction at index 1 calls a contract that emits a single 2 MiB `LOG0`;
/// transaction 0 only deploys that contract. A trace that retains logs (callTracer `withLog`,
/// directly or through a mux) is therefore charged ~2 MiB, while one that does not retain them is
/// charged nothing for the log.
///
/// Used to exercise the memory budget on the `debug_traceTransaction` / `debug_traceBlock*` path,
/// which builds its budget at a different call site than `debug_traceCall`.
pub fn init_evm_log_block(spec_id: SovSpecId) -> (Evm<C>, Storage, u64, LedgerDB) {
    let dev_signer: TestSigner = TestSigner::new_default();

    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: U256::from_str("100000000000000000000").unwrap(),
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        }],
        ..Default::default()
    };

    let (mut evm, working_set, prover_storage, ledger_db) = get_evm_with_storage(&config);

    commit(working_set, prover_storage.clone());
    let mut working_set = WorkingSet::new(prover_storage.clone());

    let l1_fee_rate = 1;
    let l2_block_info = HookL2BlockInfo {
        l2_height: 1,
        pre_state_root: [0u8; 32],
        current_spec: spec_id,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    // init code that returns the runtime `62 20 00 00 60 00 a0 00`
    // (PUSH3 0x200000; PUSH1 0x00; LOG0; STOP) - emits one 2 MiB, zero-topic log.
    let logger_deployer = vec![
        0x60, 0x08, 0x80, 0x60, 0x0b, 0x60, 0x00, 0x39, 0x60, 0x00,
        0xf3, // return runtime[0..8]
        0x62, 0x20, 0x00, 0x00, 0x60, 0x00, 0xa0, 0x00, // runtime
    ];
    let logger_contract = dev_signer.address().create(0);

    let transactions = vec![
        create_contract_message_with_bytecode(&dev_signer, 0, logger_deployer, None),
        // The 2 MiB log costs ~25M gas, far over the 1M default, so raise the gas limit (still
        // under the 30M block limit).
        dev_signer
            .sign_default_transaction_with_fee_and_gas_limit(
                TxKind::Call(logger_contract),
                vec![],
                1,
                0,
                100_000_000_000,
                29_000_000,
            )
            .unwrap(),
    ];

    let sender_address = generate_address::<C>("sender");
    let context = C::new(sender_address, 1, spec_id, l1_fee_rate);
    evm.call(
        CallMessage { txs: transactions },
        &context,
        &mut working_set,
    )
    .unwrap();

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[2u8; 32], &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());

    let mut working_set = WorkingSet::new(prover_storage.clone());
    let block_number = evm
        .block_number(&mut working_set)
        .unwrap()
        .saturating_to::<u64>();

    (evm, prover_storage, block_number, ledger_db)
}

pub fn init_evm_with_caller_contract() -> (
    Evm<C>,
    WorkingSet<<C as Spec>::Storage>,
    TestSigner,
    u64,
    LedgerDB,
) {
    let dev_signer: TestSigner = TestSigner::new_default();

    let config = EvmConfig {
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

    let (mut evm, mut working_set, prover_storage, ledger_db) = get_evm_with_storage(&config);

    let contract_addr = dev_signer.address().create(0);

    // Address of the caller contract
    // let contract_addr2: Address = Address::from_slice(
    //     hex::decode("5ccda3e6d071a059f00d4f3f25a1adc244eb5c93")
    //         .unwrap()
    //         .as_slice(),
    // );

    let l1_fee_rate = 1;
    let mut l2_height = 1;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [0u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

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

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[2u8; 32], &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());
    l2_height += 1;

    let mut working_set = WorkingSet::new(prover_storage.clone());

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [2u8; 32],
        current_spec: SovSpecId::latest(),
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    {
        let sender_address = generate_address::<C>("sender");

        let context = C::new(sender_address, l2_height, SovSpecId::latest(), l1_fee_rate);

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

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    evm.finalize_hook(&[3u8; 32], &mut working_set.accessory_state());

    commit(working_set, prover_storage.clone());
    l2_height += 1;

    let working_set = WorkingSet::new(prover_storage);
    (evm, working_set, dev_signer, l2_height, ledger_db)
}
