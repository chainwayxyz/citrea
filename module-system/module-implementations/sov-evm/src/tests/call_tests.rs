use reth_primitives::{Address, Bytes, TransactionKind, U64};
use reth_rpc_types::{CallInput, CallRequest};
use revm::primitives::{SpecId, B256, KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, StateMapAccessor, StateVecAccessor};

use crate::call::CallMessage;
use crate::evm::primitive_types::Receipt;
use crate::smart_contracts::{SelfDestructorContract, SimpleStorageContract, TestContract};
use crate::tests::genesis_tests::get_evm;
use crate::tests::test_signer::TestSigner;

use crate::{
    executor, get_cfg_env, prepare_call_env, AccountData, BlockHashContract, BlockNumberOrTag,
    EvmConfig, Filter, FilterSet, LogsContract,
};

type C = DefaultContext;

#[test]
fn call_test() {
    let (config, dev_signer, contract_addr) = get_evm_config(1000000000);

    let (evm, mut working_set) = get_evm(&config);

    evm.begin_slot_hook([5u8; 32], &[10u8; 32].into(), &mut working_set);

    let set_arg = 999;
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, 1);

        let messages = vec![
            create_contract_message(&dev_signer, 0, SimpleStorageContract::default()),
            set_arg_message(contract_addr, &dev_signer, 1, set_arg),
        ];
        for tx in messages {
            evm.call(tx, &context, &mut working_set).unwrap();
        }
    }
    evm.end_slot_hook(&mut working_set);

    let db_account = evm.accounts.get(&contract_addr, &mut working_set).unwrap();
    let storage_value = db_account
        .storage
        .get(&U256::ZERO, &mut working_set)
        .unwrap();

    assert_eq!(U256::from(set_arg), storage_value);
    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::EIP1559,
                    success: true,
                    cumulative_gas_used: 132943,
                    logs: vec![]
                },
                gas_used: 132943,
                log_index_start: 0,
                error: None
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::EIP1559,
                    success: true,
                    cumulative_gas_used: 176673,
                    logs: vec![]
                },
                gas_used: 43730,
                log_index_start: 0,
                error: None
            }
        ]
    )
}

#[test]
fn failed_transaction_test() {
    let dev_signer: TestSigner = TestSigner::new_random();
    let (evm, mut working_set) = get_evm(&EvmConfig::default());
    let working_set = &mut working_set;

    evm.begin_slot_hook([5u8; 32], &[10u8; 32].into(), working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, 1);
        let messages = vec![create_contract_message(
            &dev_signer,
            0,
            SimpleStorageContract::default(),
        )];

        for tx in messages {
            evm.call(tx, &context, working_set).unwrap();
        }
    }
    evm.end_slot_hook(working_set);

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [Receipt {
            receipt: reth_primitives::Receipt {
                tx_type: reth_primitives::TxType::EIP1559,
                success: false,
                cumulative_gas_used: 0,
                logs: vec![]
            },
            gas_used: 0,
            log_index_start: 0,
            error: Some(revm::primitives::EVMError::Transaction(
                revm::primitives::InvalidTransaction::LackOfFundForMaxFee {
                    fee: 1_000_000u64,
                    balance: U256::ZERO
                }
            ))
        }]
    )
}

#[test]
fn self_destruct_test() {
    let contract_balance: u64 = 1000000000000000;

    // address used in selfdestruct
    let die_to_address = Address::from_slice(
        hex::decode("11115497b157177315e1204f52e588b393111111")
            .unwrap()
            .as_slice(),
    );

    let (config, dev_signer, contract_addr) = get_evm_config(10000000000000000);
    let (evm, mut working_set) = get_evm(&config);

    evm.begin_slot_hook([5u8; 32], &[10u8; 32].into(), &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, 1);

        // deploy selfdestruct contract
        evm.call(
            create_contract_message(&dev_signer, 0, SelfDestructorContract::default()),
            &context,
            &mut working_set,
        )
        .unwrap();

        // send some money to the selfdestruct contract
        evm.call(
            send_money_to_contract_message(contract_addr, &dev_signer, 1, contract_balance as u128),
            &context,
            &mut working_set,
        )
        .unwrap();

        // set some variable in the contract
        evm.call(
            set_selfdestruct_arg_message(contract_addr, &dev_signer, 2, 123),
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_slot_hook(&mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let db_contract = evm
        .accounts
        .get(&contract_addr, &mut working_set)
        .expect("contract address should exist");

    // Test if we managed to send money to ocntract
    assert_eq!(db_contract.info.balance, U256::from(contract_balance));

    // Test if we managed to set the variable in the contract
    assert_eq!(
        db_contract
            .storage
            .get(&U256::from(0), &mut working_set)
            .unwrap(),
        U256::from(123)
    );

    // Test if the key is set in the keys statevec
    assert_eq!(db_contract.keys.len(&mut working_set), 1);

    evm.begin_slot_hook([5u8; 32], &[99u8; 32].into(), &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, 1);
        // selfdestruct
        evm.call(
            selfdestruct_message(contract_addr, &dev_signer, 3, die_to_address),
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_slot_hook(&mut working_set);
    let db_contract = evm
        .accounts
        .get(&contract_addr, &mut working_set)
        .expect("contract address should exist");

    let db_account = evm
        .accounts
        .get(&die_to_address, &mut working_set)
        .expect("die to address should exist");

    let receipts = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect::<Vec<_>>();

    // the tx should be a success
    assert_eq!(receipts[0].receipt.success, true);

    // after self destruct, contract balance should be 0,
    assert_eq!(db_contract.info.balance, U256::from(0));

    // the to address balance should be equal to contract balance
    assert_eq!(db_account.info.balance, U256::from(contract_balance));

    // the codehash should be 0
    assert_eq!(db_contract.info.code_hash, Default::default());

    // the nonce should be 0
    assert_eq!(db_contract.info.nonce, 0);

    // the storage should be empty
    assert_eq!(
        db_contract.storage.get(&U256::from(0), &mut working_set),
        None
    );

    // the keys should be empty
    assert_eq!(db_contract.keys.len(&mut working_set), 0);
}

#[test]
fn log_filter_test_at_block_hash() {
    let (config, dev_signer, contract_addr) = get_evm_config(10000000000000000);

    let (evm, mut working_set) = get_evm(&config);

    evm.begin_slot_hook([5u8; 32], &[10u8; 32].into(), &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, 1);

        // deploy logs contract
        evm.call(
            create_contract_message(&dev_signer, 0, LogsContract::default()),
            &context,
            &mut working_set,
        )
        .unwrap();

        // call the contract function
        evm.call(
            publish_event_message(contract_addr, &dev_signer, 1, "hello".to_string()),
            &context,
            &mut working_set,
        )
        .unwrap();
        // the last topic will be Keccak256("hello")

        // call the contract function
        evm.call(
            publish_event_message(contract_addr, &dev_signer, 2, "hi".to_string()),
            &context,
            &mut working_set,
        )
        .unwrap();
        // the last topic will be Keccak256("hi")
    }
    evm.end_slot_hook(&mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    // `AnotherLog` topics
    // [0xf16dfb875e436384c298237e04527f538a5eb71f60593cfbaae1ff23250d22a9, event signature => (kecccak256("AnotherLog(address)")
    //  0x000000000000000000000000819c5497b157177315e1204f52e588b393771719]

    // `Log`topics
    // [0xa9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7, event signature => (keccak256("Log(address,address,string,string)"))
    //  0x0000000000000000000000009e1abd37ec34bbc688b6a2b7d9387d9256cf1773,
    //  0x000000000000000000000000819c5497b157177315e1204f52e588b393771719,
    //  0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8 or 0x7624778dedc75f8b322b9fa1632a610d40b85e106c7d9bf0e743a9ce291b9c6f] (keccak256("hello") or keccak256("hi"))

    /*
       A transaction with a log with topics [A, B] will be matched by the following topic filters:
       1) [] “anything”
       2) [A] “A in first position (and anything after)”
       3) [null, B] “anything in first position AND B in second position (and anything after)”
       4) [A, B] “A in first position AND B in second position (and anything after)”
       5) [[A, B], [A, B]] “(A OR B) in first position AND (A OR B) in second position (and anything after)”
    */

    let block = evm.blocks.last(&mut working_set.accessory_state()).unwrap();
    let mut address = FilterSet::default();
    // Test without address and topics
    let mut topics: [FilterSet<B256>; 4] = [
        FilterSet::default(),
        FilterSet::default(),
        FilterSet::default(),
        FilterSet::default(),
    ];

    let filter = Filter {
        block_option: crate::FilterBlockOption::AtBlockHash(block.header.hash),
        address: address.clone(),
        topics: topics.clone(),
    };

    let rpc_logs = evm.eth_get_logs(filter, &mut working_set).unwrap();
    // should get all the logs
    assert_eq!(rpc_logs.len(), 4);

    // with address and without topics
    address.0.insert(contract_addr);

    let filter = Filter {
        block_option: crate::FilterBlockOption::AtBlockHash(block.header.hash),
        address: address.clone(),
        topics: topics.clone(),
    };
    let rpc_logs = evm.eth_get_logs(filter, &mut working_set).unwrap();
    // 1) should get all the logs
    assert_eq!(rpc_logs.len(), 4);

    let empty_topic: FilterSet<B256> = FilterSet::default();

    let mut sig_topic = FilterSet::default();
    sig_topic.0.insert(B256::from_slice(
        hex::decode("a9943ee9804b5d456d8ad7b3b1b975a5aefa607e16d13936959976e776c4bec7")
            .unwrap()
            .as_slice(),
    ));

    topics[0] = sig_topic.clone();

    let filter = Filter {
        block_option: crate::FilterBlockOption::AtBlockHash(block.header.hash),
        address: address.clone(),
        topics: topics.clone(),
    };

    let rpc_logs = evm.eth_get_logs(filter, &mut working_set).unwrap();

    // 2) should get the logs with the signature
    assert_eq!(rpc_logs.len(), 2);

    let mut last_topic = FilterSet::default();
    last_topic.0.insert(B256::from_slice(
        hex::decode("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
            .unwrap()
            .as_slice(),
    ));
    topics[0] = empty_topic;
    topics[3] = last_topic.clone();

    let filter = Filter {
        block_option: crate::FilterBlockOption::AtBlockHash(block.header.hash),
        address: address.clone(),
        topics: topics.clone(),
    };

    let rpc_logs = evm.eth_get_logs(filter, &mut working_set).unwrap();

    // 3) should get only the first log with hello as message
    assert_eq!(rpc_logs.len(), 1);
    assert_eq!(
        hex::encode(rpc_logs[0].topics[3]).to_string(),
        "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
    );

    last_topic.0.insert(B256::from_slice(
        hex::decode("7624778dedc75f8b322b9fa1632a610d40b85e106c7d9bf0e743a9ce291b9c6f")
            .unwrap()
            .as_slice(),
    ));
    topics[3] = last_topic.clone();

    let filter = Filter {
        block_option: crate::FilterBlockOption::AtBlockHash(block.header.hash),
        address: address.clone(),
        topics: topics.clone(),
    };

    let rpc_logs = evm.eth_get_logs(filter, &mut working_set).unwrap();

    // 3) should get the logs with hello and hi messages
    assert_eq!(rpc_logs.len(), 2);

    topics[0] = sig_topic.clone();
    topics[3].0.remove(&B256::from_slice(
        hex::decode("7624778dedc75f8b322b9fa1632a610d40b85e106c7d9bf0e743a9ce291b9c6f")
            .unwrap()
            .as_slice(),
    ));

    let filter = Filter {
        block_option: crate::FilterBlockOption::AtBlockHash(block.header.hash),
        address: address.clone(),
        topics: topics.clone(),
    };

    let rpc_logs = evm.eth_get_logs(filter, &mut working_set).unwrap();

    // 4) should get the logs with given signature and hello message
    assert_eq!(rpc_logs.len(), 1);

    // add the signature of anotherlog to the first topic set
    topics[0].0.insert(B256::from_slice(
        hex::decode("f16dfb875e436384c298237e04527f538a5eb71f60593cfbaae1ff23250d22a9")
            .unwrap()
            .as_slice(),
    ));
    // add the hi topic to the last topic set
    topics[3].0.insert(B256::from_slice(
        hex::decode("7624778dedc75f8b322b9fa1632a610d40b85e106c7d9bf0e743a9ce291b9c6f")
            .unwrap()
            .as_slice(),
    ));

    let filter = Filter {
        block_option: crate::FilterBlockOption::AtBlockHash(block.header.hash),
        address: address.clone(),
        topics: topics.clone(),
    };

    let rpc_logs = evm.eth_get_logs(filter, &mut working_set).unwrap();

    // 5) should get the logs with given signatures and hello or hi messages, so in this case all logs with messages
    assert_eq!(rpc_logs.len(), 2);
}

#[test]
fn log_filter_test_with_range() {
    let (config, dev_signer, contract_addr) = get_evm_config(10000000000000000);

    let (evm, mut working_set) = get_evm(&config);

    evm.begin_slot_hook([5u8; 32], &[10u8; 32].into(), &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, 1);

        // deploy selfdestruct contract
        evm.call(
            create_contract_message(&dev_signer, 0, LogsContract::default()),
            &context,
            &mut working_set,
        )
        .unwrap();

        // call the contract function
        evm.call(
            publish_event_message(contract_addr, &dev_signer, 1, "hello".to_string()),
            &context,
            &mut working_set,
        )
        .unwrap();
        // the last topic will be Keccak256("hello")

        // call the contract function
        evm.call(
            publish_event_message(contract_addr, &dev_signer, 2, "hi".to_string()),
            &context,
            &mut working_set,
        )
        .unwrap();
        // the last topic will be Keccak256("hi")
    }
    evm.end_slot_hook(&mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    // Test with block range from start to finish, should get all logs
    let empty_topics = [
        FilterSet::default(),
        FilterSet::default(),
        FilterSet::default(),
        FilterSet::default(),
    ];
    let filter = Filter {
        block_option: crate::FilterBlockOption::Range {
            from_block: Some(BlockNumberOrTag::Earliest),
            to_block: Some(BlockNumberOrTag::Latest),
        },
        address: FilterSet::default(),
        topics: empty_topics.clone(),
    };

    let rpc_logs = evm.eth_get_logs(filter, &mut working_set).unwrap();

    assert_eq!(rpc_logs.len(), 4);

    evm.begin_slot_hook([5u8; 32], &[99u8; 32].into(), &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, 1);
        // call the contract function
        evm.call(
            publish_event_message(contract_addr, &dev_signer, 3, "message".to_string()),
            &context,
            &mut working_set,
        )
        .unwrap();
        // the last topic will be Keccak256("message")
    }
    evm.end_slot_hook(&mut working_set);
    evm.finalize_hook(&[100u8; 32].into(), &mut working_set.accessory_state());
    let filter = Filter {
        block_option: crate::FilterBlockOption::Range {
            from_block: Some(BlockNumberOrTag::Latest),
            to_block: Some(BlockNumberOrTag::Latest),
        },
        address: FilterSet::default(),
        topics: empty_topics.clone(),
    };

    let rpc_logs = evm.eth_get_logs(filter, &mut working_set).unwrap();
    // In the last block we have 2 logs
    assert_eq!(rpc_logs.len(), 2);
}

#[test]
fn test_log_limits() {
    let (config, dev_signer, contract_addr) = get_evm_config(10000000000000000);

    let (evm, mut working_set) = get_evm(&config);

    evm.begin_slot_hook([5u8; 32], &[10u8; 32].into(), &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, 1);

        // deploy selfdestruct contract
        evm.call(
            create_contract_message(&dev_signer, 0, LogsContract::default()),
            &context,
            &mut working_set,
        )
        .unwrap();

        // call the contracts 10_001 times so we got 20_002 logs (response limit is 20_000)

        for i in 0..10001 {
            evm.call(
                publish_event_message(contract_addr, &dev_signer, i + 1, "hello".to_string()),
                &context,
                &mut working_set,
            )
            .unwrap();
        }
    }
    evm.end_slot_hook(&mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    // Test with block range from start to finish, should get all logs
    let empty_topics = [
        FilterSet::default(),
        FilterSet::default(),
        FilterSet::default(),
        FilterSet::default(),
    ];
    let filter = Filter {
        block_option: crate::FilterBlockOption::Range {
            from_block: Some(BlockNumberOrTag::Earliest),
            to_block: Some(BlockNumberOrTag::Latest),
        },
        address: FilterSet::default(),
        topics: empty_topics.clone(),
    };

    let rpc_logs = evm.eth_get_logs(filter, &mut working_set);

    assert!(rpc_logs.is_err());
    if let Err(rpc_err) = rpc_logs {
        assert_eq!(
            rpc_err.message(),
            "query exceeds max results 20000".to_string()
        );
    }

    // Test with block range from start to finish, should get all logs
    let empty_topics = [
        FilterSet::default(),
        FilterSet::default(),
        FilterSet::default(),
        FilterSet::default(),
    ];

    for _ in 1..100_001 {
        // generate 100_000 blocks to test the max block range limit
        evm.begin_slot_hook([5u8; 32], &[99u8; 32].into(), &mut working_set);
        evm.end_slot_hook(&mut working_set);
        evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());
    }

    // The range is greater than the default max blocks to be scanned (100_001 > 100_000)
    let filter = Filter {
        block_option: crate::FilterBlockOption::Range {
            from_block: Some(BlockNumberOrTag::Number(1)),
            to_block: Some(BlockNumberOrTag::Number(100_001)),
        },
        address: FilterSet::default(),
        topics: empty_topics.clone(),
    };

    let rpc_logs = evm.eth_get_logs(filter, &mut working_set);

    assert!(rpc_logs.is_err());
    assert_eq!(
        rpc_logs.err().unwrap().message(),
        "query exceeds max block range 100000".to_string()
    );
}

#[test]
fn test_block_hash_in_evm() {
    let (config, dev_signer, contract_addr) = get_evm_config(10000000000000000);

    let (evm, mut working_set) = get_evm(&config);
    evm.begin_slot_hook([5u8; 32], &[10u8; 32].into(), &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address);

        let deploy_message = create_contract_message(&dev_signer, 0, BlockHashContract::default());

        evm.call(deploy_message, &context, &mut working_set)
            .unwrap();
    }
    evm.end_slot_hook(&mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    for i in 0..514 {
        // generate 514 more blocks
        evm.begin_slot_hook([5u8; 32], &[99u8; 32].into(), &mut working_set);
        evm.end_slot_hook(&mut working_set);
        evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());
    }
    let last_block_number = evm
        .blocks
        .last(&mut working_set.accessory_state())
        .unwrap()
        .header
        .number;
    let block_number = last_block_number;

    let mut request = CallRequest {
        from: None,
        to: Some(contract_addr),
        gas_price: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        value: None,
        gas: None,
        input: CallInput {
            data: None,
            input: Some(
                BlockHashContract::default()
                    .get_block_hash(0)
                    .to_vec()
                    .into(),
            ),
        },
        nonce: Some(U64::from(0u64)),
        chain_id: Some(U64::from(1u64)),
        access_list: None,
        max_fee_per_blob_gas: None,
        blob_versioned_hashes: vec![],
        transaction_type: None,
    };

    for i in 0..=1000 {
        request.input.input = Some(
            BlockHashContract::default()
                .get_block_hash(i)
                .to_vec()
                .into(),
        );
        let resp = evm.get_call(request.clone(), None, None, None, &mut working_set);
        if i < 259 || i > 514 {
            // Should be 0, there is more than 256 blocks between the last block and the block number
            assert_eq!(resp.unwrap().to_vec(), vec![0u8; 32]);
        } else {
            // Should be equal to the hash in accessory state
            let block = evm
                .blocks
                .get((i) as usize, &mut working_set.accessory_state());
            assert_eq!(resp.unwrap().to_vec(), block.unwrap().header.hash.to_vec());
        }
    }
}

fn create_contract_message<T: TestContract>(
    dev_signer: &TestSigner,
    nonce: u64,
    contract: T,
) -> CallMessage {
    let signed_tx = dev_signer
        .sign_default_transaction(
            TransactionKind::Create,
            contract.byte_code().to_vec(),
            nonce,
            0,
        )
        .unwrap();

    CallMessage { tx: signed_tx }
}

fn set_selfdestruct_arg_message(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
    set_arg: u32,
) -> CallMessage {
    let contract = SimpleStorageContract::default();
    let signed_tx = dev_signer
        .sign_default_transaction(
            TransactionKind::Call(contract_addr),
            hex::decode(hex::encode(&contract.set_call_data(set_arg))).unwrap(),
            nonce,
            0,
        )
        .unwrap();

    CallMessage { tx: signed_tx }
}

fn set_arg_message(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
    set_arg: u32,
) -> CallMessage {
    let contract = SimpleStorageContract::default();
    let signed_tx = dev_signer
        .sign_default_transaction(
            TransactionKind::Call(contract_addr),
            hex::decode(hex::encode(&contract.set_call_data(set_arg))).unwrap(),
            nonce,
            0,
        )
        .unwrap();
    CallMessage { tx: signed_tx }
}

fn send_money_to_contract_message(
    contract_addr: Address,
    signer: &TestSigner,
    nonce: u64,
    value: u128,
) -> CallMessage {
    let signed_tx = signer
        .sign_default_transaction(
            TransactionKind::Call(contract_addr),
            vec![].into(),
            nonce,
            value,
        )
        .unwrap();
    CallMessage { tx: signed_tx }
}

fn selfdestruct_message(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
    to_address: Address,
) -> CallMessage {
    let contract = SelfDestructorContract::default();
    let signed_tx = dev_signer
        .sign_default_transaction(
            TransactionKind::Call(contract_addr),
            hex::decode(hex::encode(&contract.selfdestruct(to_address))).unwrap(),
            nonce,
            0,
        )
        .unwrap();
    CallMessage { tx: signed_tx }
}

fn publish_event_message(
    contract_addr: Address,
    signer: &TestSigner,
    nonce: u64,
    message: String,
) -> CallMessage {
    let contract = LogsContract::default();
    let signed_tx = signer
        .sign_default_transaction(
            TransactionKind::Call(contract_addr),
            hex::decode(hex::encode(&contract.publish_event(message))).unwrap(),
            nonce,
            0,
        )
        .unwrap();
    CallMessage { tx: signed_tx }
}

fn get_evm_config(signer_balance: u64) -> (EvmConfig, TestSigner, Address) {
    let dev_signer: TestSigner = TestSigner::new_random();

    let contract_addr: Address = Address::from_slice(
        hex::decode("819c5497b157177315e1204f52e588b393771719")
            .unwrap()
            .as_slice(),
    );
    let config = EvmConfig {
        data: vec![AccountData {
            address: dev_signer.address(),
            balance: U256::from(signer_balance),
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
        }],
        spec: vec![(0, SpecId::SHANGHAI)].into_iter().collect(),
        ..Default::default()
    };
    (config, dev_signer, contract_addr)
}
