use std::collections::HashMap;
use std::str::FromStr;

use alloy_primitives::LogData;
use reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT;
use reth_primitives::{address, b256, hex, BlockNumberOrTag, Log, TxKind, U64};
use reth_rpc_types::{TransactionInput, TransactionRequest};
use revm::primitives::{Bytes, KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, StateMapAccessor, StateVecAccessor};
use sov_rollup_interface::spec::SpecId;

use crate::call::CallMessage;
use crate::evm::primitive_types::Receipt;
use crate::evm::system_contracts::BitcoinLightClient;
use crate::handler::L1_FEE_OVERHEAD;
use crate::smart_contracts::{BlockHashContract, LogsContract};
use crate::system_contracts::{BridgeWrapper, ProxyAdmin};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{
    config_push_contracts, create_contract_message, create_contract_message_with_fee, get_evm,
    get_evm_config_starting_base_fee, publish_event_message,
};
use crate::{AccountData, BASE_FEE_VAULT, L1_FEE_VAULT, SYSTEM_SIGNER};

type C = DefaultContext;

#[test]
fn test_sys_bitcoin_light_client() {
    let (mut config, dev_signer, _) =
        get_evm_config_starting_base_fee(U256::from_str("10000000000000").unwrap(), None, 1);

    config_push_contracts(&mut config, None);
    let (mut evm, mut working_set) = get_evm(&config);

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [
            Receipt { // BitcoinLightClient::initializeBlockNumber(U256)
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 50751,
                    logs: vec![]
                },
                gas_used: 50751,
                log_index_start: 0,
                l1_diff_size: 255,
            },
            Receipt { // BitcoinLightClient::setBlockInfo(U256, U256)
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 131371,
                    logs: vec![
                        Log {
                            address: BitcoinLightClient::address(),
                            data: LogData::new(
                                vec![b256!("32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f")],
                                Bytes::from_static(&hex!("000000000000000000000000000000000000000000000000000000000000000101010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202")),
                            ).unwrap(),
                        }
                    ]
                },
                gas_used: 80620,
                log_index_start: 0,
                l1_diff_size: 561,
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 300521,
                    logs: vec![
                        Log {
                            address: BridgeWrapper::address(),
                            data: LogData::new(
                                vec![b256!("fbe5b6cbafb274f445d7fed869dc77a838d8243a22c460de156560e8857cad03")],
                                Bytes::from_static(&hex!("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead")),
                            ).unwrap(),
                        },
                        Log {
                            address: BridgeWrapper::address(),
                            data: LogData::new(
                                vec![b256!("80bd1fdfe157286ce420ee763f91748455b249605748e5df12dad9844402bafc")],
                                Bytes::from_static(&hex!("000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000002d4a209fb3a961d8b1f4ec1caa220c6a50b815febc0b689ddf0b9ddfbf99cb74479e41ac0063066369747265611400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a08000000003b9aca006800000000000000000000000000000000000000000000"))
                            ).unwrap(),
                        }
                    ]
                },
                gas_used: 169150,
                log_index_start: 1,
                l1_diff_size: 1019,
            }
        ]
    );

    // checkout esad/fix-block-env-bug branch
    let tx = evm
        .get_transaction_by_block_number_and_index(
            BlockNumberOrTag::Number(1),
            U64::from(0),
            &mut working_set,
        )
        .unwrap()
        .unwrap();

    assert_eq!(tx.block_number.unwrap(), 1);

    let l1_fee_rate = 1;
    let l2_height = 2;

    let system_account = evm.accounts.get(&SYSTEM_SIGNER, &mut working_set).unwrap();
    // The system caller balance is unchanged(if exists)/or should be 0
    assert_eq!(system_account.balance, U256::from(0));
    assert_eq!(system_account.nonce, 3);

    let hash = evm
        .get_call(
            TransactionRequest {
                to: Some(TxKind::Call(BitcoinLightClient::address())),
                input: TransactionInput::new(BitcoinLightClient::get_block_hash(1)),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    let merkle_root = evm
        .get_call(
            TransactionRequest {
                to: Some(TxKind::Call(BitcoinLightClient::address())),
                input: TransactionInput::new(BitcoinLightClient::get_witness_root_by_number(1)),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    assert_eq!(hash.as_ref(), &[1u8; 32]);
    assert_eq!(merkle_root.as_ref(), &[2u8; 32]);

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [2u8; 32],
        da_slot_height: 2,
        da_slot_txs_commitment: [3u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 42,
    };

    // New L1 block №2
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(
            sender_address,
            sequencer_address,
            l2_height,
            SpecId::Genesis,
            l1_fee_rate,
        );

        let deploy_message = create_contract_message_with_fee(
            &dev_signer,
            0,
            BlockHashContract::default(),
            10000000,
        );

        evm.call(
            CallMessage {
                txs: vec![deploy_message],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let system_account = evm.accounts.get(&SYSTEM_SIGNER, &mut working_set).unwrap();
    // The system caller balance is unchanged(if exists)/or should be 0
    assert_eq!(system_account.balance, U256::from(0));
    assert_eq!(system_account.nonce, 4);

    let receipts: Vec<_> = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect();
    assert_eq!(receipts.len(), 5); // 3 from first L2 block + 2 from second L2 block
    let receipts = receipts[3..].to_vec();

    assert_eq!(receipts,
        [
            Receipt { // BitcoinLightClient::setBlockInfo(U256, U256)
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 80620,
                    logs: vec![
                        Log {
                            address: BitcoinLightClient::address(),
                            data: LogData::new(
                                vec![b256!("32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f")],
                                Bytes::from_static(&hex!("000000000000000000000000000000000000000000000000000000000000000202020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303")),
                            ).unwrap(),
                        }
                    ]
                },
                gas_used: 80620,
                log_index_start: 0,
                l1_diff_size: 561,
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 194855,
                    logs: vec![]
                },
                gas_used: 114235,
                log_index_start: 1,
                l1_diff_size: 479,
            },
        ]
    );
    let base_fee_vault = evm.accounts.get(&BASE_FEE_VAULT, &mut working_set).unwrap();
    let l1_fee_vault = evm.accounts.get(&L1_FEE_VAULT, &mut working_set).unwrap();

    assert_eq!(base_fee_vault.balance, U256::from(114235u64 * 10000000));
    assert_eq!(l1_fee_vault.balance, U256::from(479 + L1_FEE_OVERHEAD));

    let hash = evm
        .get_call(
            TransactionRequest {
                to: Some(TxKind::Call(BitcoinLightClient::address())),
                input: TransactionInput::new(BitcoinLightClient::get_block_hash(2)),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    let merkle_root = evm
        .get_call(
            TransactionRequest {
                to: Some(TxKind::Call(BitcoinLightClient::address())),
                input: TransactionInput::new(BitcoinLightClient::get_witness_root_by_number(2)),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    assert_eq!(hash.as_ref(), &[2u8; 32]);
    assert_eq!(merkle_root.as_ref(), &[3u8; 32]);
}

#[test]
fn test_sys_tx_gas_usage_effect_on_block_gas_limit() {
    // This test also tests evm checking gas usage and not just the tx gas limit when including txs in block after checking available block limit
    // For example txs below have 1_000_000 gas limit, the block used to stuck at 29_030_000 gas usage but now can utilize the whole block gas limit
    let (mut config, dev_signer, contract_addr) = get_evm_config_starting_base_fee(
        U256::from_str("100000000000000000000").unwrap(),
        Some(ETHEREUM_BLOCK_GAS_LIMIT),
        1,
    );

    config_push_contracts(&mut config, None);

    let (mut evm, mut working_set) = get_evm(&config);
    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let sender_address = generate_address::<C>("sender");
    let sequencer_address = generate_address::<C>("sequencer");
    let context = C::new(
        sender_address,
        sequencer_address,
        l2_height,
        SpecId::Genesis,
        l1_fee_rate,
    );

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate: 1,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        // deploy logs contract
        evm.call(
            CallMessage {
                txs: vec![create_contract_message(
                    &dev_signer,
                    0,
                    LogsContract::default(),
                )],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    l2_height += 1;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [10u8; 32],
        da_slot_height: 2,
        da_slot_txs_commitment: [43u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(
            sender_address,
            sequencer_address,
            l2_height,
            SpecId::Genesis,
            l1_fee_rate,
        );

        let sys_tx_gas_usage = evm.get_pending_txs_cumulative_gas_used(&mut working_set);
        assert_eq!(sys_tx_gas_usage, 80620);

        let mut rlp_transactions = Vec::new();

        // Check: Given now we also push bridge contract, is the following calculation correct?

        // the amount of gas left is 30_000_000 - 80620 = 29_919_380
        // send barely enough gas to reach the limit
        // one publish event message is 26388 gas
        // 29919380 / 26388 = 1133.82
        // so there cannot be more than 1133 messages
        for i in 0..11350 {
            rlp_transactions.push(publish_event_message(
                contract_addr,
                &dev_signer,
                i + 1,
                "hello".to_string(),
            ));
        }

        evm.call(
            CallMessage {
                txs: rlp_transactions,
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let block = evm
        .get_block_by_number(Some(BlockNumberOrTag::Latest), None, &mut working_set)
        .unwrap()
        .unwrap();

    assert_eq!(block.header.gas_limit, ETHEREUM_BLOCK_GAS_LIMIT as _);
    assert!(block.header.gas_used <= block.header.gas_limit);

    // In total there should only be 1134 transactions 1 is system tx others are contract calls
    assert!(
        block.transactions.hashes().len() == 1134,
        "Some transactions should be dropped because of gas limit"
    );
}

#[test]
fn test_bridge() {
    let (mut config, _, _) =
        get_evm_config_starting_base_fee(U256::from_str("1000000").unwrap(), None, 1);

    config_push_contracts(&mut config, None);

    let (mut evm, mut working_set) = get_evm(&config);

    let l1_fee_rate = 1;
    let l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_height: 2,
        da_slot_hash: [2u8; 32],
        da_slot_txs_commitment: [
            35, 6, 15, 121, 7, 142, 70, 109, 219, 14, 211, 34, 120, 157, 121, 127, 164, 53, 23, 80,
            188, 45, 73, 146, 108, 41, 125, 77, 133, 86, 235, 104,
        ],
        pre_state_root: [1u8; 32].to_vec(),
        current_spec: SpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 32, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 42, 1, 145, 22, 58, 104, 30, 248, 81, 242, 63, 79, 72, 216, 243, 241, 44,
            60, 88, 230, 44, 206, 194, 243, 103, 224, 237, 31, 108, 29, 207, 112, 110, 94, 1, 0, 0,
            0, 0, 253, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 87, 2, 248, 199, 154, 59, 0, 0, 0, 0, 34, 81, 32, 180, 253, 103, 250, 242,
            234, 221, 209, 124, 86, 77, 184, 249, 147, 86, 132, 180, 238, 191, 207, 88, 164, 131,
            206, 164, 3, 244, 185, 120, 165, 30, 115, 74, 1, 0, 0, 0, 0, 0, 0, 34, 0, 32, 74, 232,
            21, 114, 240, 110, 27, 136, 253, 92, 237, 122, 26, 0, 9, 69, 67, 46, 131, 225, 85, 30,
            111, 114, 30, 233, 192, 11, 140, 195, 50, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 207, 3,
            64, 161, 192, 181, 26, 246, 26, 75, 97, 75, 195, 25, 148, 167, 73, 18, 169, 134, 223,
            209, 191, 199, 220, 243, 38, 223, 51, 57, 71, 136, 182, 41, 246, 233, 200, 87, 9, 234,
            172, 247, 185, 237, 10, 63, 152, 75, 134, 182, 168, 7, 69, 187, 91, 93, 123, 216, 163,
            176, 231, 145, 122, 34, 105, 83, 11, 74, 32, 159, 179, 169, 97, 216, 177, 244, 236, 28,
            170, 34, 12, 106, 80, 184, 21, 254, 188, 11, 104, 157, 223, 11, 157, 223, 191, 153,
            203, 116, 71, 158, 65, 172, 0, 99, 6, 99, 105, 116, 114, 101, 97, 20, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 8, 0, 0, 0, 0, 59, 154, 202, 0, 104, 65, 192,
            147, 199, 55, 141, 150, 81, 138, 117, 68, 136, 33, 196, 247, 200, 244, 186, 231, 206,
            96, 248, 4, 208, 61, 31, 6, 40, 221, 93, 208, 245, 222, 81, 37, 229, 146, 81, 60, 96,
            31, 142, 155, 205, 125, 11, 153, 65, 84, 235, 108, 14, 51, 249, 43, 190, 34, 128, 62,
            188, 105, 97, 131, 159, 232, 139, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 96, 188, 220, 18, 179, 65, 54, 53, 162, 189, 161, 197, 39, 81, 59, 20, 229, 165, 93,
            101, 210, 169, 210, 96, 211, 140, 243, 192, 109, 227, 37, 32, 132, 152, 138, 124, 199,
            15, 227, 162, 158, 170, 41, 163, 87, 12, 45, 65, 82, 173, 194, 121, 81, 159, 172, 64,
            111, 49, 209, 54, 230, 132, 109, 96, 16, 58, 248, 121, 131, 161, 31, 16, 228, 37, 59,
            51, 252, 102, 244, 110, 239, 88, 105, 90, 152, 229, 212, 121, 74, 52, 180, 88, 100,
            172, 192, 227, 205,
        ]
        .to_vec()],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let recipient_address = address!("0101010101010101010101010101010101010101");
    let recipient_account = evm
        .accounts
        .get(&recipient_address, &mut working_set)
        .unwrap();

    assert_eq!(
        recipient_account.balance,
        U256::from_str("0x8ac7230489e80000").unwrap(),
    );
}

#[test]
fn test_upgrade_light_client() {
    // initialize_logging(tracing::Level::INFO);
    let (mut config, _, _) = get_evm_config_starting_base_fee(
        U256::from_str("1000000000000000000000").unwrap(),
        None,
        1,
    );

    config_push_contracts(&mut config, None);

    // False bitcoin light client implementation, returns dead address on block hash query
    config.data.push(AccountData::new(
        address!("deAD00000000000000000000000000000000dEAd"),
        U256::ZERO,
        Bytes::from_static(&hex!("6080604052600436106101145760003560e01c8063715018a6116100a0578063d269a03e11610064578063d269a03e14610332578063d761753e14610352578063e30c39781461037a578063ee82ac5e1461038f578063f2fde38b146103cf57600080fd5b8063715018a61461027057806379ba5097146102855780638da5cb5b1461029a578063a91d8b3d146102c7578063ad3cb1cc146102f457600080fd5b80634f1ef286116100e75780634f1ef286146101c85780634ffd344a146101db57806352d1902d1461020b57806357e871e71461022057806361b207e21461023657600080fd5b80630466efc4146101195780630e27bc11146101595780631f5783331461017b57806334cdf78d1461019b575b600080fd5b34801561012557600080fd5b50610146610134366004610cec565b60009081526002602052604090205490565b6040519081526020015b60405180910390f35b34801561016557600080fd5b50610179610174366004610d05565b6103ef565b005b34801561018757600080fd5b50610179610196366004610cec565b610518565b3480156101a757600080fd5b506101466101b6366004610cec565b60016020526000908152604090205481565b6101796101d6366004610d59565b6105c6565b3480156101e757600080fd5b506101fb6101f6366004610e64565b6105dd565b6040519015158152602001610150565b34801561021757600080fd5b50610146610603565b34801561022c57600080fd5b5061014660005481565b34801561024257600080fd5b50610146610251366004610cec565b6000908152600160209081526040808320548352600290915290205490565b34801561027c57600080fd5b50610179610632565b34801561029157600080fd5b50610179610646565b3480156102a657600080fd5b506102af61068e565b6040516001600160a01b039091168152602001610150565b3480156102d357600080fd5b506101466102e2366004610cec565b60026020526000908152604090205481565b34801561030057600080fd5b50610325604051806040016040528060058152602001640352e302e360dc1b81525081565b6040516101509190610ee3565b34801561033e57600080fd5b506101fb61034d366004610e64565b6106c3565b34801561035e57600080fd5b506102af73deaddeaddeaddeaddeaddeaddeaddeaddeaddead81565b34801561038657600080fd5b506102af6106d2565b34801561039b57600080fd5b506101466103aa366004610cec565b507fdeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead90565b3480156103db57600080fd5b506101796103ea366004610f16565b6106fb565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146104575760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c65720060448201526064015b60405180910390fd5b600080549081900361049d5760405162461bcd60e51b815260206004820152600f60248201526e139bdd081a5b9a5d1a585b1a5e9959608a1b604482015260640161044e565b60008181526001602081905260409091208490556104bc908290610f31565b6000908155838152600260209081526040808320859055915482519081529081018590529081018390527f32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f9060600160405180910390a1505050565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead1461057b5760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c657200604482015260640161044e565b600054156105c15760405162461bcd60e51b8152602060048201526013602482015272105b1c9958591e481a5b9a5d1a585b1a5e9959606a1b604482015260640161044e565b600055565b6105cf82610780565b6105d98282610788565b5050565b6000858152600160205260408120546105f9908686868661085c565b9695505050505050565b600061060d6108ba565b507f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc90565b61063a610903565b6106446000610935565b565b33806106506106d2565b6001600160a01b0316146106825760405163118cdaa760e01b81526001600160a01b038216600482015260240161044e565b61068b81610935565b50565b6000807f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c1993005b546001600160a01b031692915050565b60006105f9868686868661085c565b6000807f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c006106b3565b610703610903565b7f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c0080546001600160a01b0319166001600160a01b038316908117825561074761068e565b6001600160a01b03167f38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e2270060405160405180910390a35050565b61068b610903565b816001600160a01b03166352d1902d6040518163ffffffff1660e01b8152600401602060405180830381865afa9250505080156107e2575060408051601f3d908101601f191682019092526107df91810190610f52565b60015b61080a57604051634c9c8ce360e01b81526001600160a01b038316600482015260240161044e565b7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc811461084d57604051632a87526960e21b81526004810182905260240161044e565b610857838361096d565b505050565b6000858152600260209081526040808320548151601f8701849004840281018401909252858252916108af91889184919089908990819084018382808284376000920191909152508992506109c3915050565b979650505050505050565b306001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146106445760405163703e46dd60e11b815260040160405180910390fd5b3361090c61068e565b6001600160a01b0316146106445760405163118cdaa760e01b815233600482015260240161044e565b7f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c0080546001600160a01b03191681556105d982610a01565b61097682610a72565b6040516001600160a01b038316907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a28051156109bb576108578282610ae9565b6105d9610b61565b600083851480156109d2575081155b80156109dd57508251155b156109ea575060016109f9565b6109f685848685610b80565b90505b949350505050565b7f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c19930080546001600160a01b031981166001600160a01b03848116918217845560405192169182907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a3505050565b806001600160a01b03163b600003610aa857604051634c9c8ce360e01b81526001600160a01b038216600482015260240161044e565b7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc80546001600160a01b0319166001600160a01b0392909216919091179055565b6060600080846001600160a01b031684604051610b069190610f6b565b600060405180830381855af49150503d8060008114610b41576040519150601f19603f3d011682016040523d82523d6000602084013e610b46565b606091505b5091509150610b56858383610c2a565b925050505b92915050565b34156106445760405163b398979f60e01b815260040160405180910390fd5b600060208451610b909190610f87565b15610b9d575060006109f9565b8351600003610bae575060006109f9565b818560005b8651811015610c1d57610bc7600284610f87565b600103610beb57610be4610bde8883016020015190565b83610c89565b9150610c04565b610c0182610bfc8984016020015190565b610c89565b91505b60019290921c91610c16602082610f31565b9050610bb3565b5090931495945050505050565b606082610c3f57610c3a82610c95565b610c82565b8151158015610c5657506001600160a01b0384163b155b15610c7f57604051639996b31560e01b81526001600160a01b038516600482015260240161044e565b50805b9392505050565b6000610c828383610cbe565b805115610ca55780518082602001fd5b604051630a12f52160e11b815260040160405180910390fd5b60008260005281602052602060006040600060025afa50602060006020600060025afa505060005192915050565b600060208284031215610cfe57600080fd5b5035919050565b60008060408385031215610d1857600080fd5b50508035926020909101359150565b80356001600160a01b0381168114610d3e57600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b60008060408385031215610d6c57600080fd5b610d7583610d27565b9150602083013567ffffffffffffffff80821115610d9257600080fd5b818501915085601f830112610da657600080fd5b813581811115610db857610db8610d43565b604051601f8201601f19908116603f01168101908382118183101715610de057610de0610d43565b81604052828152886020848701011115610df957600080fd5b8260208601602083013760006020848301015280955050505050509250929050565b60008083601f840112610e2d57600080fd5b50813567ffffffffffffffff811115610e4557600080fd5b602083019150836020828501011115610e5d57600080fd5b9250929050565b600080600080600060808688031215610e7c57600080fd5b8535945060208601359350604086013567ffffffffffffffff811115610ea157600080fd5b610ead88828901610e1b565b96999598509660600135949350505050565b60005b83811015610eda578181015183820152602001610ec2565b50506000910152565b6020815260008251806020840152610f02816040850160208701610ebf565b601f01601f19169190910160400192915050565b600060208284031215610f2857600080fd5b610c8282610d27565b80820180821115610b5b57634e487b7160e01b600052601160045260246000fd5b600060208284031215610f6457600080fd5b5051919050565b60008251610f7d818460208701610ebf565b9190910192915050565b600082610fa457634e487b7160e01b600052601260045260246000fd5b50069056fea2646970667358221220cb22b346a23078243cb869a68fb68e5704b567765a15214f1d3d3d7cadb59a9764736f6c63430008190033")),
        0,
        HashMap::new()
    ));

    // secret key is 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
    let contract_owner = TestSigner::new(
        secp256k1::SecretKey::from_slice(&[
            0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38,
            0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b,
            0xf4, 0xf2, 0xff, 0x80,
        ])
        .unwrap(),
    );

    config.data.push(AccountData {
        address: contract_owner.address(),
        balance: U256::from_str("1000000000000000000000").unwrap(),
        code_hash: KECCAK_EMPTY,
        code: Bytes::default(),
        nonce: 0,
        storage: Default::default(),
    });

    let (mut evm, mut working_set) = get_evm(&config);

    let l1_fee_rate = 1;
    let l2_height = 2;

    let sender_address = generate_address::<C>("sender");
    let sequencer_address = generate_address::<C>("sequencer");
    let context = C::new(
        sender_address,
        sequencer_address,
        l2_height,
        SpecId::Genesis,
        l1_fee_rate,
    );

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    let upgrade_tx = contract_owner
        .sign_default_transaction(
            TxKind::Call(ProxyAdmin::address()),
            ProxyAdmin::upgrade(
                BitcoinLightClient::address(),
                address!("deAD00000000000000000000000000000000dEAd"),
            )
            .to_vec(),
            0,
            0,
        )
        .unwrap();
    evm.call(
        CallMessage {
            txs: vec![upgrade_tx],
        },
        &context,
        &mut working_set,
    )
    .unwrap();

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let hash = evm
        .get_call(
            TransactionRequest {
                to: Some(TxKind::Call(BitcoinLightClient::address())),
                input: TransactionInput::new(BitcoinLightClient::get_block_hash(0)),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    // Assert if hash is equal to 0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead
    assert_eq!(
        hash,
        reth_primitives::Bytes::from_str(
            "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
        )
        .unwrap()
    );
}

#[test]
fn test_change_upgrade_owner() {
    let (mut config, _, _) = get_evm_config_starting_base_fee(
        U256::from_str("1000000000000000000000").unwrap(),
        None,
        1,
    );

    config_push_contracts(&mut config, None);

    let contract_owner = TestSigner::new(
        secp256k1::SecretKey::from_slice(&[
            0xac, 0x09, 0x74, 0xbe, 0xc3, 0x9a, 0x17, 0xe3, 0x6b, 0xa4, 0xa6, 0xb4, 0xd2, 0x38,
            0xff, 0x94, 0x4b, 0xac, 0xb4, 0x78, 0xcb, 0xed, 0x5e, 0xfc, 0xae, 0x78, 0x4d, 0x7b,
            0xf4, 0xf2, 0xff, 0x80,
        ])
        .unwrap(),
    );

    // An arbitrary private key
    let new_contract_owner = TestSigner::new(
        secp256k1::SecretKey::from_slice(&[
            0x1c, 0x6b, 0x8c, 0xac, 0x22, 0xd9, 0x9f, 0xc7, 0xc1, 0x24, 0xb9, 0xcd, 0x0d, 0xe2,
            0xd3, 0xfa, 0x1f, 0xa1, 0xfa, 0xef, 0x42, 0x0b, 0xfe, 0x79, 0x1d, 0x8c, 0x36, 0x2d,
            0x76, 0x5e, 0x22, 0x70,
        ])
        .unwrap(),
    );

    config.data.push(AccountData {
        address: contract_owner.address(),
        balance: U256::from_str("1000000000000000000000").unwrap(),
        code_hash: KECCAK_EMPTY,
        code: Bytes::default(),
        nonce: 0,
        storage: Default::default(),
    });

    config.data.push(AccountData {
        address: new_contract_owner.address(),
        balance: U256::from_str("1000000000000000000000").unwrap(),
        code_hash: KECCAK_EMPTY,
        code: Bytes::default(),
        nonce: 0,
        storage: Default::default(),
    });

    // False bitcoin light client implementation, returns dead address on block hash query, added to test upgrading
    config.data.push(AccountData::new(
        address!("deAD00000000000000000000000000000000dEAd"),
        U256::ZERO,
        Bytes::from_static(&hex!("6080604052600436106101145760003560e01c8063715018a6116100a0578063d269a03e11610064578063d269a03e14610332578063d761753e14610352578063e30c39781461037a578063ee82ac5e1461038f578063f2fde38b146103cf57600080fd5b8063715018a61461027057806379ba5097146102855780638da5cb5b1461029a578063a91d8b3d146102c7578063ad3cb1cc146102f457600080fd5b80634f1ef286116100e75780634f1ef286146101c85780634ffd344a146101db57806352d1902d1461020b57806357e871e71461022057806361b207e21461023657600080fd5b80630466efc4146101195780630e27bc11146101595780631f5783331461017b57806334cdf78d1461019b575b600080fd5b34801561012557600080fd5b50610146610134366004610cec565b60009081526002602052604090205490565b6040519081526020015b60405180910390f35b34801561016557600080fd5b50610179610174366004610d05565b6103ef565b005b34801561018757600080fd5b50610179610196366004610cec565b610518565b3480156101a757600080fd5b506101466101b6366004610cec565b60016020526000908152604090205481565b6101796101d6366004610d59565b6105c6565b3480156101e757600080fd5b506101fb6101f6366004610e64565b6105dd565b6040519015158152602001610150565b34801561021757600080fd5b50610146610603565b34801561022c57600080fd5b5061014660005481565b34801561024257600080fd5b50610146610251366004610cec565b6000908152600160209081526040808320548352600290915290205490565b34801561027c57600080fd5b50610179610632565b34801561029157600080fd5b50610179610646565b3480156102a657600080fd5b506102af61068e565b6040516001600160a01b039091168152602001610150565b3480156102d357600080fd5b506101466102e2366004610cec565b60026020526000908152604090205481565b34801561030057600080fd5b50610325604051806040016040528060058152602001640352e302e360dc1b81525081565b6040516101509190610ee3565b34801561033e57600080fd5b506101fb61034d366004610e64565b6106c3565b34801561035e57600080fd5b506102af73deaddeaddeaddeaddeaddeaddeaddeaddeaddead81565b34801561038657600080fd5b506102af6106d2565b34801561039b57600080fd5b506101466103aa366004610cec565b507fdeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead90565b3480156103db57600080fd5b506101796103ea366004610f16565b6106fb565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146104575760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c65720060448201526064015b60405180910390fd5b600080549081900361049d5760405162461bcd60e51b815260206004820152600f60248201526e139bdd081a5b9a5d1a585b1a5e9959608a1b604482015260640161044e565b60008181526001602081905260409091208490556104bc908290610f31565b6000908155838152600260209081526040808320859055915482519081529081018590529081018390527f32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f9060600160405180910390a1505050565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead1461057b5760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c657200604482015260640161044e565b600054156105c15760405162461bcd60e51b8152602060048201526013602482015272105b1c9958591e481a5b9a5d1a585b1a5e9959606a1b604482015260640161044e565b600055565b6105cf82610780565b6105d98282610788565b5050565b6000858152600160205260408120546105f9908686868661085c565b9695505050505050565b600061060d6108ba565b507f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc90565b61063a610903565b6106446000610935565b565b33806106506106d2565b6001600160a01b0316146106825760405163118cdaa760e01b81526001600160a01b038216600482015260240161044e565b61068b81610935565b50565b6000807f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c1993005b546001600160a01b031692915050565b60006105f9868686868661085c565b6000807f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c006106b3565b610703610903565b7f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c0080546001600160a01b0319166001600160a01b038316908117825561074761068e565b6001600160a01b03167f38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e2270060405160405180910390a35050565b61068b610903565b816001600160a01b03166352d1902d6040518163ffffffff1660e01b8152600401602060405180830381865afa9250505080156107e2575060408051601f3d908101601f191682019092526107df91810190610f52565b60015b61080a57604051634c9c8ce360e01b81526001600160a01b038316600482015260240161044e565b7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc811461084d57604051632a87526960e21b81526004810182905260240161044e565b610857838361096d565b505050565b6000858152600260209081526040808320548151601f8701849004840281018401909252858252916108af91889184919089908990819084018382808284376000920191909152508992506109c3915050565b979650505050505050565b306001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146106445760405163703e46dd60e11b815260040160405180910390fd5b3361090c61068e565b6001600160a01b0316146106445760405163118cdaa760e01b815233600482015260240161044e565b7f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c0080546001600160a01b03191681556105d982610a01565b61097682610a72565b6040516001600160a01b038316907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a28051156109bb576108578282610ae9565b6105d9610b61565b600083851480156109d2575081155b80156109dd57508251155b156109ea575060016109f9565b6109f685848685610b80565b90505b949350505050565b7f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c19930080546001600160a01b031981166001600160a01b03848116918217845560405192169182907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a3505050565b806001600160a01b03163b600003610aa857604051634c9c8ce360e01b81526001600160a01b038216600482015260240161044e565b7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc80546001600160a01b0319166001600160a01b0392909216919091179055565b6060600080846001600160a01b031684604051610b069190610f6b565b600060405180830381855af49150503d8060008114610b41576040519150601f19603f3d011682016040523d82523d6000602084013e610b46565b606091505b5091509150610b56858383610c2a565b925050505b92915050565b34156106445760405163b398979f60e01b815260040160405180910390fd5b600060208451610b909190610f87565b15610b9d575060006109f9565b8351600003610bae575060006109f9565b818560005b8651811015610c1d57610bc7600284610f87565b600103610beb57610be4610bde8883016020015190565b83610c89565b9150610c04565b610c0182610bfc8984016020015190565b610c89565b91505b60019290921c91610c16602082610f31565b9050610bb3565b5090931495945050505050565b606082610c3f57610c3a82610c95565b610c82565b8151158015610c5657506001600160a01b0384163b155b15610c7f57604051639996b31560e01b81526001600160a01b038516600482015260240161044e565b50805b9392505050565b6000610c828383610cbe565b805115610ca55780518082602001fd5b604051630a12f52160e11b815260040160405180910390fd5b60008260005281602052602060006040600060025afa50602060006020600060025afa505060005192915050565b600060208284031215610cfe57600080fd5b5035919050565b60008060408385031215610d1857600080fd5b50508035926020909101359150565b80356001600160a01b0381168114610d3e57600080fd5b919050565b634e487b7160e01b600052604160045260246000fd5b60008060408385031215610d6c57600080fd5b610d7583610d27565b9150602083013567ffffffffffffffff80821115610d9257600080fd5b818501915085601f830112610da657600080fd5b813581811115610db857610db8610d43565b604051601f8201601f19908116603f01168101908382118183101715610de057610de0610d43565b81604052828152886020848701011115610df957600080fd5b8260208601602083013760006020848301015280955050505050509250929050565b60008083601f840112610e2d57600080fd5b50813567ffffffffffffffff811115610e4557600080fd5b602083019150836020828501011115610e5d57600080fd5b9250929050565b600080600080600060808688031215610e7c57600080fd5b8535945060208601359350604086013567ffffffffffffffff811115610ea157600080fd5b610ead88828901610e1b565b96999598509660600135949350505050565b60005b83811015610eda578181015183820152602001610ec2565b50506000910152565b6020815260008251806020840152610f02816040850160208701610ebf565b601f01601f19169190910160400192915050565b600060208284031215610f2857600080fd5b610c8282610d27565b80820180821115610b5b57634e487b7160e01b600052601160045260246000fd5b600060208284031215610f6457600080fd5b5051919050565b60008251610f7d818460208701610ebf565b9190910192915050565b600082610fa457634e487b7160e01b600052601260045260246000fd5b50069056fea2646970667358221220cb22b346a23078243cb869a68fb68e5704b567765a15214f1d3d3d7cadb59a9764736f6c63430008190033")),
        0,
        HashMap::new()
    ));

    let (mut evm, mut working_set) = get_evm(&config);

    let l1_fee_rate = 1;
    let mut l2_height = 2;
    let sender_address = generate_address::<C>("sender");
    let sequencer_address = generate_address::<C>("sequencer");
    let context = C::new(
        sender_address,
        sequencer_address,
        l2_height,
        SpecId::Genesis,
        l1_fee_rate,
    );

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    let change_owner_tx = contract_owner
        .sign_default_transaction(
            TxKind::Call(ProxyAdmin::address()),
            ProxyAdmin::transfer_ownership(new_contract_owner.address()).to_vec(),
            0,
            0,
        )
        .unwrap();

    evm.call(
        CallMessage {
            txs: vec![change_owner_tx],
        },
        &context,
        &mut working_set,
    )
    .unwrap();

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    l2_height += 1;
    let context = C::new(
        sender_address,
        sequencer_address,
        l2_height,
        SpecId::Genesis,
        l1_fee_rate,
    );

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    // New owner should be able to upgrade the contract

    let upgrade_tx = new_contract_owner
        .sign_default_transaction(
            TxKind::Call(ProxyAdmin::address()),
            ProxyAdmin::upgrade(
                BitcoinLightClient::address(),
                address!("deAD00000000000000000000000000000000dEAd"),
            )
            .to_vec(),
            0,
            0,
        )
        .unwrap();

    evm.call(
        CallMessage {
            txs: vec![upgrade_tx],
        },
        &context,
        &mut working_set,
    )
    .unwrap();

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let provided_new_owner = evm
        .get_call(
            TransactionRequest {
                to: Some(TxKind::Call(ProxyAdmin::address())),
                input: TransactionInput::new(ProxyAdmin::owner()),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    assert_eq!(
        provided_new_owner.to_vec()[12..],
        new_contract_owner.address().to_vec()
    );

    let hash = evm
        .get_call(
            TransactionRequest {
                to: Some(TxKind::Call(BitcoinLightClient::address())),
                input: TransactionInput::new(BitcoinLightClient::get_block_hash(0)),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    // Assert if hash is equal to 0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead
    assert_eq!(
        hash,
        reth_primitives::Bytes::from_str(
            "0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
        )
        .unwrap()
    );
}
