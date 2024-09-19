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
use crate::system_contracts::{Bridge, ProxyAdmin};
use crate::tests::call_tests::{
    create_contract_message, create_contract_message_with_fee, get_evm_config_starting_base_fee,
    publish_event_message,
};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::get_evm;
use crate::{AccountData, EvmConfig, BASE_FEE_VAULT, L1_FEE_VAULT, SYSTEM_SIGNER};

type C = DefaultContext;

#[test]
fn test_sys_bitcoin_light_client() {
    let (mut config, dev_signer, _) =
        get_evm_config_starting_base_fee(U256::from_str("10000000000000").unwrap(), None, 1);

    config_push_contracts(&mut config);

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
                    cumulative_gas_used: 131471,
                    logs: vec![
                        Log {
                            address: BitcoinLightClient::address(),
                            data: LogData::new(
                                vec![b256!("32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f")],
                                Bytes::from_static(&hex!("000000000000000000000000000000000000000000000000000000000000000201010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202")),
                            ).unwrap(),
                        }
                    ]
                },
                gas_used: 80720,
                log_index_start: 0,
                l1_diff_size: 561,
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 300621,
                    logs: vec![
                        Log {
                            address: Bridge::address(),
                            data: LogData::new(
                                vec![b256!("fbe5b6cbafb274f445d7fed869dc77a838d8243a22c460de156560e8857cad03")],
                                Bytes::from_static(&hex!("0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000deaddeaddeaddeaddeaddeaddeaddeaddeaddead")),
                            ).unwrap(),
                        },
                        Log {
                            address: Bridge::address(),
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
                    cumulative_gas_used: 80720,
                    logs: vec![
                        Log {
                            address: BitcoinLightClient::address(),
                            data: LogData::new(
                                vec![b256!("32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f")],
                                Bytes::from_static(&hex!("000000000000000000000000000000000000000000000000000000000000000302020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303")),
                            ).unwrap(),
                        }
                    ]
                },
                gas_used: 80720,
                log_index_start: 0,
                l1_diff_size: 561,
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 194955,
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

    config_push_contracts(&mut config);

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
        assert_eq!(sys_tx_gas_usage, 80720);

        let mut rlp_transactions = Vec::new();

        // Check: Given now we also push bridge contract, is the following calculation correct?

        // the amount of gas left is 30_000_000 - 80720 = 29_919_280
        // send barely enough gas to reach the limit
        // one publish event message is 26388 gas
        // 29919280 / 26388 = 1133.82
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

    config_push_contracts(&mut config);

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

    config_push_contracts(&mut config);

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

    config_push_contracts(&mut config);

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

fn config_push_contracts(config: &mut EvmConfig) {
    config.data.push(AccountData::new(
        BitcoinLightClient::address(),
        U256::ZERO,
        Bytes::from_static(&hex!("60806040523661001357610011610017565b005b6100115b61001f610169565b6001600160a01b0316330361015f5760606001600160e01b0319600035166364d3180d60e11b810161005a5761005361019c565b9150610157565b63587086bd60e11b6001600160e01b031982160161007a576100536101f3565b63070d7c6960e41b6001600160e01b031982160161009a57610053610239565b621eb96f60e61b6001600160e01b03198216016100b95761005361026a565b63a39f25e560e01b6001600160e01b03198216016100d9576100536102aa565b60405162461bcd60e51b815260206004820152604260248201527f5472616e73706172656e745570677261646561626c6550726f78793a2061646d60448201527f696e2063616e6e6f742066616c6c6261636b20746f2070726f78792074617267606482015261195d60f21b608482015260a4015b60405180910390fd5b815160208301f35b6101676102be565b565b60007fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b546001600160a01b0316919050565b60606101a66102ce565b60006101b53660048184610683565b8101906101c291906106c9565b90506101df816040518060200160405280600081525060006102d9565b505060408051602081019091526000815290565b60606000806102053660048184610683565b81019061021291906106fa565b91509150610222828260016102d9565b604051806020016040528060008152509250505090565b60606102436102ce565b60006102523660048184610683565b81019061025f91906106c9565b90506101df81610305565b60606102746102ce565b600061027e610169565b604080516001600160a01b03831660208201529192500160405160208183030381529060405291505090565b60606102b46102ce565b600061027e61035c565b6101676102c961035c565b61036b565b341561016757600080fd5b6102e28361038f565b6000825111806102ef5750805b15610300576102fe83836103cf565b505b505050565b7f7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f61032e610169565b604080516001600160a01b03928316815291841660208301520160405180910390a1610359816103fb565b50565b60006103666104a4565b905090565b3660008037600080366000845af43d6000803e80801561038a573d6000f35b3d6000fd5b610398816104cc565b6040516001600160a01b038216907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a250565b60606103f4838360405180606001604052806027815260200161083860279139610560565b9392505050565b6001600160a01b0381166104605760405162461bcd60e51b815260206004820152602660248201527f455243313936373a206e65772061646d696e20697320746865207a65726f206160448201526564647265737360d01b606482015260840161014e565b807fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b80546001600160a01b0319166001600160a01b039290921691909117905550565b60007f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc61018d565b6001600160a01b0381163b6105395760405162461bcd60e51b815260206004820152602d60248201527f455243313936373a206e657720696d706c656d656e746174696f6e206973206e60448201526c1bdd08184818dbdb9d1c9858dd609a1b606482015260840161014e565b807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc610483565b6060600080856001600160a01b03168560405161057d91906107e8565b600060405180830381855af49150503d80600081146105b8576040519150601f19603f3d011682016040523d82523d6000602084013e6105bd565b606091505b50915091506105ce868383876105d8565b9695505050505050565b60608315610647578251600003610640576001600160a01b0385163b6106405760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e7472616374000000604482015260640161014e565b5081610651565b6106518383610659565b949350505050565b8151156106695781518083602001fd5b8060405162461bcd60e51b815260040161014e9190610804565b6000808585111561069357600080fd5b838611156106a057600080fd5b5050820193919092039150565b80356001600160a01b03811681146106c457600080fd5b919050565b6000602082840312156106db57600080fd5b6103f4826106ad565b634e487b7160e01b600052604160045260246000fd5b6000806040838503121561070d57600080fd5b610716836106ad565b9150602083013567ffffffffffffffff81111561073257600080fd5b8301601f8101851361074357600080fd5b803567ffffffffffffffff81111561075d5761075d6106e4565b604051601f8201601f19908116603f0116810167ffffffffffffffff8111828210171561078c5761078c6106e4565b6040528181528282016020018710156107a457600080fd5b816020840160208301376000602083830101528093505050509250929050565b60005b838110156107df5781810151838201526020016107c7565b50506000910152565b600082516107fa8184602087016107c4565b9190910192915050565b60208152600082518060208401526108238160408501602087016107c4565b601f01601f1916919091016040019291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564")),
        0,
        [
            (U256::from_be_slice(&hex!("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")), U256::from_be_slice(&hex!("0000000000000000000000003200000000000000000000000000000000000001"))),
            (U256::from_be_slice(&hex!("b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")), U256::from_be_slice(&hex!("00000000000000000000000031ffffffffffffffffffffffffffffffffffffff"))),
        ].into_iter().collect(),
    ));

    config.data.push(AccountData::new(
        address!("3200000000000000000000000000000000000001"),
        U256::ZERO,
        Bytes::from_static(&hex!("608060405234801561001057600080fd5b50600436106100a95760003560e01c806357e871e71161007157806357e871e71461014c57806361b207e214610155578063a91d8b3d14610182578063d269a03e146101a2578063d761753e146101b5578063ee82ac5e146101e857600080fd5b80630466efc4146100ae5780630e27bc11146100e15780631f578333146100f657806334cdf78d146101095780634ffd344a14610129575b600080fd5b6100ce6100bc366004610598565b60009081526002602052604090205490565b6040519081526020015b60405180910390f35b6100f46100ef3660046105b1565b610208565b005b6100f4610104366004610598565b610330565b6100ce610117366004610598565b60016020526000908152604090205481565b61013c61013736600461061c565b6103de565b60405190151581526020016100d8565b6100ce60005481565b6100ce610163366004610598565b6000908152600160209081526040808320548352600290915290205490565b6100ce610190366004610598565b60026020526000908152604090205481565b61013c6101b036600461061c565b610404565b6101d073deaddeaddeaddeaddeaddeaddeaddeaddeaddead81565b6040516001600160a01b0390911681526020016100d8565b6100ce6101f6366004610598565b60009081526001602052604090205490565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146102705760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c65720060448201526064015b60405180910390fd5b60008054908190036102b65760405162461bcd60e51b815260206004820152600f60248201526e139bdd081a5b9a5d1a585b1a5e9959608a1b6044820152606401610267565b60008181526001602081905260409091208490556102d5908290610677565b60009081558381526002602090815260409182902084905581518381529081018590529081018390527f32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f9060600160405180910390a1505050565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146103935760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c6572006044820152606401610267565b600054156103d95760405162461bcd60e51b8152602060048201526013602482015272105b1c9958591e481a5b9a5d1a585b1a5e9959606a1b6044820152606401610267565b600055565b6000858152600160205260408120546103fa908686868661040f565b9695505050505050565b60006103fa86868686865b6000858152600260209081526040808320548151601f870184900484028101840190925285825291610462918891849190899089908190840183828082843760009201919091525089925061046d915050565b979650505050505050565b6000838514801561047c575081155b801561048757508251155b15610494575060016104a3565b6104a0858486856104ab565b90505b949350505050565b6000602084516104bb9190610698565b156104c8575060006104a3565b83516000036104d9575060006104a3565b818560005b8651811015610548576104f2600284610698565b6001036105165761050f6105098883016020015190565b83610555565b915061052f565b61052c826105278984016020015190565b610555565b91505b60019290921c91610541602082610677565b90506104de565b5090931495945050505050565b6000610561838361056a565b90505b92915050565b60008260005281602052602060006040600060025afa50602060006020600060025afa505060005192915050565b6000602082840312156105aa57600080fd5b5035919050565b600080604083850312156105c457600080fd5b50508035926020909101359150565b60008083601f8401126105e557600080fd5b50813567ffffffffffffffff8111156105fd57600080fd5b60208301915083602082850101111561061557600080fd5b9250929050565b60008060008060006080868803121561063457600080fd5b8535945060208601359350604086013567ffffffffffffffff81111561065957600080fd5b610665888289016105d3565b96999598509660600135949350505050565b8082018082111561056457634e487b7160e01b600052601160045260246000fd5b6000826106b557634e487b7160e01b600052601260045260246000fd5b50069056")),
        0,
        HashMap::new()
    ));

    config.data.push(AccountData::new(
        Bridge::address(),
        U256::from_str("0x115EEC47F6CF7E35000000").unwrap(),
        Bytes::from_static(&hex!("60806040523661001357610011610017565b005b6100115b61001f610169565b6001600160a01b0316330361015f5760606001600160e01b0319600035166364d3180d60e11b810161005a5761005361019c565b9150610157565b63587086bd60e11b6001600160e01b031982160161007a576100536101f3565b63070d7c6960e41b6001600160e01b031982160161009a57610053610239565b621eb96f60e61b6001600160e01b03198216016100b95761005361026a565b63a39f25e560e01b6001600160e01b03198216016100d9576100536102aa565b60405162461bcd60e51b815260206004820152604260248201527f5472616e73706172656e745570677261646561626c6550726f78793a2061646d60448201527f696e2063616e6e6f742066616c6c6261636b20746f2070726f78792074617267606482015261195d60f21b608482015260a4015b60405180910390fd5b815160208301f35b6101676102be565b565b60007fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b546001600160a01b0316919050565b60606101a66102ce565b60006101b53660048184610683565b8101906101c291906106c9565b90506101df816040518060200160405280600081525060006102d9565b505060408051602081019091526000815290565b60606000806102053660048184610683565b81019061021291906106fa565b91509150610222828260016102d9565b604051806020016040528060008152509250505090565b60606102436102ce565b60006102523660048184610683565b81019061025f91906106c9565b90506101df81610305565b60606102746102ce565b600061027e610169565b604080516001600160a01b03831660208201529192500160405160208183030381529060405291505090565b60606102b46102ce565b600061027e61035c565b6101676102c961035c565b61036b565b341561016757600080fd5b6102e28361038f565b6000825111806102ef5750805b15610300576102fe83836103cf565b505b505050565b7f7e644d79422f17c01e4894b5f4f588d331ebfa28653d42ae832dc59e38c9798f61032e610169565b604080516001600160a01b03928316815291841660208301520160405180910390a1610359816103fb565b50565b60006103666104a4565b905090565b3660008037600080366000845af43d6000803e80801561038a573d6000f35b3d6000fd5b610398816104cc565b6040516001600160a01b038216907fbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b90600090a250565b60606103f4838360405180606001604052806027815260200161083860279139610560565b9392505050565b6001600160a01b0381166104605760405162461bcd60e51b815260206004820152602660248201527f455243313936373a206e65772061646d696e20697320746865207a65726f206160448201526564647265737360d01b606482015260840161014e565b807fb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d61035b80546001600160a01b0319166001600160a01b039290921691909117905550565b60007f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc61018d565b6001600160a01b0381163b6105395760405162461bcd60e51b815260206004820152602d60248201527f455243313936373a206e657720696d706c656d656e746174696f6e206973206e60448201526c1bdd08184818dbdb9d1c9858dd609a1b606482015260840161014e565b807f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc610483565b6060600080856001600160a01b03168560405161057d91906107e8565b600060405180830381855af49150503d80600081146105b8576040519150601f19603f3d011682016040523d82523d6000602084013e6105bd565b606091505b50915091506105ce868383876105d8565b9695505050505050565b60608315610647578251600003610640576001600160a01b0385163b6106405760405162461bcd60e51b815260206004820152601d60248201527f416464726573733a2063616c6c20746f206e6f6e2d636f6e7472616374000000604482015260640161014e565b5081610651565b6106518383610659565b949350505050565b8151156106695781518083602001fd5b8060405162461bcd60e51b815260040161014e9190610804565b6000808585111561069357600080fd5b838611156106a057600080fd5b5050820193919092039150565b80356001600160a01b03811681146106c457600080fd5b919050565b6000602082840312156106db57600080fd5b6103f4826106ad565b634e487b7160e01b600052604160045260246000fd5b6000806040838503121561070d57600080fd5b610716836106ad565b9150602083013567ffffffffffffffff81111561073257600080fd5b8301601f8101851361074357600080fd5b803567ffffffffffffffff81111561075d5761075d6106e4565b604051601f8201601f19908116603f0116810167ffffffffffffffff8111828210171561078c5761078c6106e4565b6040528181528282016020018710156107a457600080fd5b816020840160208301376000602083830101528093505050509250929050565b60005b838110156107df5781810151838201526020016107c7565b50506000910152565b600082516107fa8184602087016107c4565b9190910192915050565b60208152600082518060208401526108238160408501602087016107c4565b601f01601f1916919091016040019291505056fe416464726573733a206c6f772d6c6576656c2064656c65676174652063616c6c206661696c6564")),
        0,
        [
            (U256::from_be_slice(&hex!("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc")), U256::from_be_slice(&hex!("0000000000000000000000003200000000000000000000000000000000000002"))),
            (U256::from_be_slice(&hex!("9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300")), U256::from_be_slice(&hex!("000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266"))),
            (U256::from_be_slice(&hex!("b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103")), U256::from_be_slice(&hex!("00000000000000000000000031ffffffffffffffffffffffffffffffffffffff")))
        ].into_iter().collect(),
    ));

    config.data.push(AccountData::new(
        address!("3200000000000000000000000000000000000002"),
        U256::ZERO,
        Bytes::from_static(&hex!("60806040526004361061019c5760003560e01c80638786dba7116100ec578063d761753e1161008a578063e613ae0011610064578063e613ae001461048e578063f119a9bd146104a9578063f2fde38b146104c9578063f8e655d2146104e957600080fd5b8063d761753e14610431578063dd95c7c614610459578063e30c39781461047957600080fd5b8063a41c5cf3116100c6578063a41c5cf3146103af578063b3ab15fb146103c4578063bafa9eb2146103e4578063c045577b1461040457600080fd5b80638786dba71461037257806387f8bf56146103855780638da5cb5b1461039a57600080fd5b8063570ca73511610159578063715018a611610133578063715018a61461031357806374ab4a8314610328578063781952a81461034857806379ba50971461035d57600080fd5b8063570ca735146102945780635d3e3176146102d15780635e3cc740146102f357600080fd5b806311e53a01146101a1578063158ef93e146101e1578063198546231461020b5780634126013714610220578063419759f514610240578063471ba1e314610256575b600080fd5b3480156101ad57600080fd5b506101ce6101bc3660046129ee565b60276020526000908152604090205481565b6040519081526020015b60405180910390f35b3480156101ed57600080fd5b506000546101fb9060ff1681565b60405190151581526020016101d8565b61021e610219366004612a4b565b610509565b005b34801561022c57600080fd5b5061021e61023b366004612afb565b6106e2565b34801561024c57600080fd5b506101ce60215481565b34801561026257600080fd5b506102766102713660046129ee565b6108ef565b604080519283526001600160e01b03199091166020830152016101d8565b3480156102a057600080fd5b506000546102b99061010090046001600160a01b031681565b6040516001600160a01b0390911681526020016101d8565b3480156102dd57600080fd5b506102e6610920565b6040516101d89190612b96565b3480156102ff57600080fd5b5061021e61030e366004612be2565b6109ae565b34801561031f57600080fd5b5061021e610d65565b34801561033457600080fd5b5061021e610343366004612c1e565b610d79565b34801561035457600080fd5b506026546101ce565b34801561036957600080fd5b5061021e610f4c565b61021e610380366004612c88565b610f94565b34801561039157600080fd5b506102e66110bb565b3480156103a657600080fd5b506102b96110c8565b3480156103bb57600080fd5b506102e66110fd565b3480156103d057600080fd5b5061021e6103df366004612cb4565b61110a565b3480156103f057600080fd5b506101fb6103ff3660046129ee565b61117b565b34801561041057600080fd5b506101ce61041f3660046129ee565b60286020526000908152604090205481565b34801561043d57600080fd5b506102b973deaddeaddeaddeaddeaddeaddeaddeaddeaddead81565b34801561046557600080fd5b5061021e610474366004612be2565b6111a6565b34801561048557600080fd5b506102b9611606565b34801561049a57600080fd5b506102b96001603160981b0181565b3480156104b557600080fd5b5061021e6104c4366004612cdd565b61162f565b3480156104d557600080fd5b5061021e6104e4366004612cb4565b6116a3565b3480156104f557600080fd5b5061021e610504366004612d1e565b611728565b82811461054f5760405162461bcd60e51b815260206004820152600f60248201526e098cadccee8d040dad2e6dac2e8c6d608b1b60448201526064015b60405180910390fd5b60215461055d908490612d97565b34146105a55760405162461bcd60e51b8152602060048201526017602482015276125b9d985b1a59081dda5d1a191c985dc8185b5bdd5b9d604a1b6044820152606401610546565b60265460005b848110156106da57600060405180604001604052808888858181106105d2576105d2612dae565b9050602002013581526020018686858181106105f0576105f0612dae565b90506020020160208101906106059190612dc4565b6001600160e01b03191690526026805460018101825560009190915281517f744a2cf8fd7008e3d53b67916e73460df9fa5214e3ef23dd4259ca09493a359460029092029182015560208201517f744a2cf8fd7008e3d53b67916e73460df9fa5214e3ef23dd4259ca09493a3595909101805463ffffffff191660e09290921c91909117905590507f3311a04a346a103ac115cca33028a2bc82f1964805860d0d3fc84a2772496ada816106b98486612ddf565b426040516106c993929190612df2565b60405180910390a1506001016105ab565b505050505050565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146107455760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c6572006044820152606401610546565b60005460ff16156107985760405162461bcd60e51b815260206004820152601f60248201527f436f6e747261637420697320616c726561647920696e697469616c697a6564006044820152606401610546565b806000036107e85760405162461bcd60e51b815260206004820152601a60248201527f4465706f73697420616d6f756e742063616e6e6f7420626520300000000000006044820152606401610546565b60008490036108095760405162461bcd60e51b815260040161054690612e20565b6000805460ff191660011790556023610823858783612ef0565b506024610831838583612ef0565b50602181905560008054610100600160a81b03191674deaddeaddeaddeaddeaddeaddeaddeaddeaddead001781556040805191825273deaddeaddeaddeaddeaddeaddeaddeaddeaddead60208301527ffbe5b6cbafb274f445d7fed869dc77a838d8243a22c460de156560e8857cad03910160405180910390a17f80bd1fdfe157286ce420ee763f91748455b249605748e5df12dad9844402bafc858585856040516108e09493929190612fd8565b60405180910390a15050505050565b602681815481106108ff57600080fd5b60009182526020909120600290910201805460019091015490915060e01b82565b6025805461092d90612e6d565b80601f016020809104026020016040519081016040528092919081815260200182805461095990612e6d565b80156109a65780601f1061097b576101008083540402835291602001916109a6565b820191906000526020600020905b81548152906001019060200180831161098957829003601f168201915b505050505081565b6109b7816117a2565b5060009050610a066109cc606084018461300a565b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250611ac592505050565b915060009050610a63610a1c606085018561300a565b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250610a5e925060019150869050613050565b611adc565b90506000610a7082611c54565b90506000610a88610a8383836020611cd6565b611d99565b90506000610aa9610a836020808651610aa19190613050565b869190611cd6565b600083815260276020526040812054919250819003610b015760405162461bcd60e51b815260206004820152601460248201527311195c1bdcda5d08191bc81b9bdd08195e1a5cdd60621b6044820152606401610546565b6000610b4d610b1360808a018a61300a565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201829052509250611e1e915050565b90506000610b5c826001611f01565b9050600060258054610b6d90612e6d565b915060009050610b7e838284611cd6565b9050610c148160258054610b9190612e6d565b80601f0160208091040260200160405190810160405280929190818152602001828054610bbd90612e6d565b8015610c0a5780601f10610bdf57610100808354040283529160200191610c0a565b820191906000526020600020905b815481529060010190602001808311610bed57829003601f168201915b5050505050612085565b610c605760405162461bcd60e51b815260206004820152601a60248201527f496e76616c696420736c6173684f7254616b65207363726970740000000000006044820152606401610546565b6000602881610c70600189613050565b815260200190815260200160002054905060008160001480610c9a5750610c968861215c565b8214155b905080610ce95760405162461bcd60e51b815260206004820152601960248201527f4f70657261746f72206973206e6f74206d616c6963696f7573000000000000006044820152606401610546565b600180896103e88110610cfe57610cfe612dae565b602091828204019190066101000a81548160ff0219169083151502179055507ff918cdaebea74c5a8c3b02d7404c162f507551b158202cedcba9b6a74eabdff288604051610d4e91815260200190565b60405180910390a150505050505050505050505050565b610d6d612169565b610d77600061219b565b565b610d82836117a2565b5060009050610dd3610d97604086018661300a565b8080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152508792506121d7915050565b90506000610de08261232a565b90506000610ded83612337565b9050600060268581548110610e0457610e04612dae565b60009182526020918290206040805180820190915260029290920201805480835260019091015460e01b6001600160e01b03191692820192909252915083148015610e665750816001600160e01b03191681602001516001600160e01b031916145b610ea65760405162461bcd60e51b81526020600482015260116024820152706e6f74206d61746368696e67205554584f60781b6044820152606401610546565b6000610eb86109cc60608a018a61300a565b915060009050610ece610a1c60608b018b61300a565b90506000610edb82611c54565b90506000610ee882611d99565b9050610ef38161215c565b60008a8152602860209081526040918290209290925580518b81529182018390527feedf47c2f61b040827944fd45e44ef6d742354b34e1af7dd99a56f444ec79347910160405180910390a15050505050505050505050565b3380610f56611606565b6001600160a01b031614610f885760405163118cdaa760e01b81526001600160a01b0382166004820152602401610546565b610f918161219b565b50565b6021543414610fdf5760405162461bcd60e51b8152602060048201526017602482015276125b9d985b1a59081dda5d1a191c985dc8185b5bdd5b9d604a1b6044820152606401610546565b6040805180820182528381526001600160e01b03198316602082019081526026805460018101825560009190915282517f744a2cf8fd7008e3d53b67916e73460df9fa5214e3ef23dd4259ca09493a3594600283029081019190915591517f744a2cf8fd7008e3d53b67916e73460df9fa5214e3ef23dd4259ca09493a3595909201805463ffffffff191660e09390931c9290921790915591519091907f3311a04a346a103ac115cca33028a2bc82f1964805860d0d3fc84a2772496ada906110ad90849084904290612df2565b60405180910390a150505050565b6024805461092d90612e6d565b6000807f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c1993005b546001600160a01b031692915050565b6023805461092d90612e6d565b611112612169565b60008054610100600160a81b0319166101006001600160a01b038481168281029390931793849055604080519290940416815260208101919091527ffbe5b6cbafb274f445d7fed869dc77a838d8243a22c460de156560e8857cad03910160405180910390a150565b6001816103e8811061118c57600080fd5b60209182820401919006915054906101000a900460ff1681565b60005461010090046001600160a01b031633146112055760405162461bcd60e51b815260206004820152601a60248201527f63616c6c6572206973206e6f7420746865206f70657261746f720000000000006044820152606401610546565b600080611211836117a2565b915091508060011461125e5760405162461bcd60e51b815260206004820152601660248201527513db9b1e481bdb99481a5b9c1d5d08185b1b1bddd95960521b6044820152606401610546565b60006113096112706020860186612dc4565b61127d604087018761300a565b8080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506112bf92505050606088018861300a565b8080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506113049250505060c0890160a08a01612dc4565b612344565b6000818152602760205260409020549091501561135d5760405162461bcd60e51b81526020600482015260126024820152711d1e125908185b1c9958591e481cdc195b9d60721b6044820152606401610546565b60226000815461136c90613063565b9182905550600082815260276020526040812091909155611393610b13608087018761300a565b905060006113a082611ac5565b915050806003146113eb5760405162461bcd60e51b8152602060048201526015602482015274496e76616c6964207769746e657373206974656d7360581b6044820152606401610546565b60006113f8836001611f01565b905060006023805461140990612e6d565b91506000905061141a838284611cd6565b905061142d8160238054610b9190612e6d565b6114725760405162461bcd60e51b8152602060048201526016602482015275125b9d985b1a590819195c1bdcda5d081cd8dc9a5c1d60521b6044820152606401610546565b60006114a66024805461148490612e6d565b86516114909250613050565b6024805461149d90612e6d565b87929150611cd6565b90506114b98160248054610b9190612e6d565b6114fd5760405162461bcd60e51b8152602060048201526015602482015274092dcecc2d8d2c840e6c6e4d2e0e840e6eaccccd2f605b1b6044820152606401610546565b600061150885612374565b602254604080518d8152602081018c90526001600160a01b038416818301524260608201526080810192909252519192507fa82453ca34121b3ecb910d957824e27c5dc6465315949facd15fb72886490058919081900360a00190a16021546040516000916001600160a01b038416918381818185875af1925050503d80600081146115b0576040519150601f19603f3d011682016040523d82523d6000602084013e6115b5565b606091505b50509050806115f85760405162461bcd60e51b815260206004820152600f60248201526e151c985b9cd9995c8819985a5b1959608a1b6044820152606401610546565b505050505050505050505050565b6000807f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c006110ed565b611637612169565b60008190036116585760405162461bcd60e51b815260040161054690612e20565b6025611665828483612ef0565b507f8578c80bdea3ff51431011ed88db9cb415de2cf64f9ed5e7137288268cbdeb2c828260405161169792919061307c565b60405180910390a15050565b6116ab612169565b7f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c0080546001600160a01b0319166001600160a01b03831690811782556116ef6110c8565b6001600160a01b03167f38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e2270060405160405180910390a35050565b611730612169565b60008390036117515760405162461bcd60e51b815260040161054690612e20565b602361175e848683612ef0565b50602461176c828483612ef0565b507f80bd1fdfe157286ce420ee763f91748455b249605748e5df12dad9844402bafc848484846040516110ad9493929190612fd8565b600080806118026117b66020860186612dc4565b6117c66040870160208801613090565b6117d3604088018861300a565b6117e060608a018a61300a565b6117ed60808c018c61300a565b6117fd60c08e0160a08f01612dc4565b6123aa565b905061184e611814604086018661300a565b8080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506123de92505050565b61189a5760405162461bcd60e51b815260206004820152601d60248201527f56696e206973206e6f742070726f7065726c7920666f726d61747465640000006044820152606401610546565b6118e46118aa606086018661300a565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525061248292505050565b6119305760405162461bcd60e51b815260206004820152601e60248201527f566f7574206973206e6f742070726f7065726c7920666f726d617474656400006044820152606401610546565b60006119426109cc604087018761300a565b91506119929050611956608087018761300a565b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250859250612519915050565b6119e85760405162461bcd60e51b815260206004820152602160248201527f5769746e657373206973206e6f742070726f7065726c7920666f726d617474656044820152601960fa1b6064820152608401610546565b6001603160981b01634ffd344a60e087013584611a0860c08a018a61300a565b8a61010001356040518663ffffffff1660e01b8152600401611a2e9594939291906130ba565b602060405180830381865afa158015611a4b573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611a6f91906130ec565b611abb5760405162461bcd60e51b815260206004820152601b60248201527f5472616e73616374696f6e206973206e6f7420696e20626c6f636b00000000006044820152606401610546565b9094909350915050565b600080611ad383600061258e565b91509150915091565b6060600080611aea85611ac5565b909250905060018201611b0f5760405162461bcd60e51b81526004016105469061310e565b808410611b525760405162461bcd60e51b81526020600482015260116024820152702b37baba103932b0b21037bb32b9393ab760791b6044820152606401610546565b600080611b60846001612ddf565b905060005b86811015611bde57611b778883612730565b92506000198303611bca5760405162461bcd60e51b815260206004820152601a60248201527f42616420566172496e7420696e207363726970745075626b65790000000000006044820152606401610546565b611bd48383612ddf565b9150600101611b65565b50611be98782612730565b91506000198203611c3c5760405162461bcd60e51b815260206004820152601a60248201527f42616420566172496e7420696e207363726970745075626b65790000000000006044820152606401610546565b611c47878284611cd6565b9450505050505b92915050565b606081600981518110611c6957611c69612dae565b6020910101516001600160f81b031916603560f91b14611c9757505060408051602081019091526000815290565b600082600a81518110611cac57611cac612dae565b01602001516001600160f81b031981169150611ccf908490600b9060f81c611cd6565b9392505050565b606081600003611cf55750604080516020810190915260008152611ccf565b6000611d018385612ddf565b90508381118015611d13575080855110155b611d555760405162461bcd60e51b8152602060048201526013602482015272536c696365206f7574206f6620626f756e647360681b6044820152606401610546565b604051915082604083010160405282825283850182038460208701018481015b80821015611d8e57815183830152602082019150611d75565b505050509392505050565b60008151600003611dac57506000919050565b81516020811115611e0a5760405162461bcd60e51b815260206004820152602260248201527f42797465732063616e6e6f74206265206d6f7265207468616e20333220627974604482015261657360f01b6064820152608401610546565b60209283015192036008029190911c919050565b606060008060005b84811015611e9757611e388683612794565b92506000198303611e835760405162461bcd60e51b815260206004820152601560248201527442616420566172496e7420696e207769746e65737360581b6044820152606401610546565b611e8d8383612ddf565b9150600101611e26565b50611ea28582612794565b91506000198203611eed5760405162461bcd60e51b815260206004820152601560248201527442616420566172496e7420696e207769746e65737360581b6044820152606401610546565b611ef8858284611cd6565b95945050505050565b6060600080611f0f85611ac5565b909250905060018201611f345760405162461bcd60e51b81526004016105469061310e565b808410611f765760405162461bcd60e51b815260206004820152601060248201526f2b34b7103932b0b21037bb32b9393ab760811b6044820152606401610546565b600080611f84846001612ddf565b905060005b8681101561200f57611f9b888361258e565b909550925060018301611fe55760405162461bcd60e51b815260206004820152601260248201527142616420566172496e7420696e206974656d60701b6044820152606401610546565b82611ff1866001612ddf565b611ffb9190612ddf565b6120059083612ddf565b9150600101611f89565b5061201a878261258e565b9094509150600182016120645760405162461bcd60e51b815260206004820152601260248201527142616420566172496e7420696e206974656d60701b6044820152606401610546565b611c47816120728685612ddf565b61207d906001612ddf565b899190611cd6565b8151815160009190811461209d576000915050611c4e565b60206000805b8383116120d357505084810151848201516020909201918082146120ce576000945050505050611c4e565b6120a3565b60006120e0602085613050565b90505b8481101561214e578681815181106120fd576120fd612dae565b602001015160f81c60f81b6001600160f81b03191688828151811061212457612124612dae565b01602001516001600160f81b0319161461214657600095505050505050611c4e565b6001016120e3565b506001979650505050505050565b6000611c4e826001612ddf565b336121726110c8565b6001600160a01b031614610d775760405163118cdaa760e01b8152336004820152602401610546565b7f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c0080546001600160a01b03191681556121d382612836565b5050565b60606000806121e585611ac5565b90925090506001820161220a5760405162461bcd60e51b81526004016105469061310e565b80841061224c5760405162461bcd60e51b815260206004820152601060248201526f2b34b7103932b0b21037bb32b9393ab760811b6044820152606401610546565b60008061225a846001612ddf565b905060005b868110156122d25761227188836128a7565b925060001983036122be5760405162461bcd60e51b815260206004820152601760248201527642616420566172496e7420696e2073637269707453696760481b6044820152606401610546565b6122c88383612ddf565b915060010161225f565b506122dd87826128a7565b91506000198203611c3c5760405162461bcd60e51b815260206004820152601760248201527642616420566172496e7420696e2073637269707453696760481b6044820152606401610546565b6020810151600090611c4e565b6000611c4e8260206128f0565b6000611ef8858585856040516020016123609493929190613150565b6040516020818303038152906040526128ff565b6000806023805461238490612e6d565b91506000905061239684836014611cd6565b61239f906131ad565b60601c949350505050565b60006123d08a8a8a8a8a8a8a8a8a60405160200161236099989796959493929190613200565b9a9950505050505050505050565b60008060006123ec84611ac5565b90925090508015806123ff575060001982145b1561240e575060009392505050565b600061241b836001612ddf565b905060005b82811015612475578551821061243c5750600095945050505050565b600061244887846128a7565b90506000198103612460575060009695505050505050565b61246a8184612ddf565b925050600101612420565b5093519093149392505050565b600080600061249084611ac5565b90925090508015806124a3575060001982145b156124b2575060009392505050565b60006124bf836001612ddf565b905060005b8281101561247557855182106124e05750600095945050505050565b60006124ec8784612730565b90506000198103612504575060009695505050505050565b61250e8184612ddf565b9250506001016124c4565b60008160000361252b57506000611c4e565b6000805b83811015612582578451821061254a57600092505050611c4e565b60006125568684612794565b9050600019810361256d5760009350505050611c4e565b6125778184612ddf565b92505060010161252f565b50835114905092915050565b600080600061259d8585612926565b90508060ff166000036125d25760008585815181106125be576125be612dae565b016020015190935060f81c91506127299050565b836125de826001613269565b60ff166125eb9190612ddf565b855110156126025760001960009250925050612729565b60008160ff166002036126465761263b612627612620876001612ddf565b88906128f0565b62ffff0060e882901c1660f89190911c1790565b61ffff16905061271f565b8160ff1660040361269557612688612662612620876001612ddf565b60d881901c63ff00ff001662ff00ff60e89290921c9190911617601081811b91901c1790565b63ffffffff16905061271f565b8160ff1660080361271f576127136126b1612620876001612ddf565b60c01c64ff000000ff600882811c91821665ff000000ff009390911b92831617601090811b6001600160401b031666ff00ff00ff00ff9290921667ff00ff00ff00ff009093169290921790911c65ffff0000ffff1617602081811c91901b1790565b6001600160401b031690505b60ff909116925090505b9250929050565b600061273d826009612ddf565b8351101561274e5750600019611c4e565b60008061276585612760866008612ddf565b61258e565b90925090506001820161277e5760001992505050611c4e565b8061278a836009612ddf565b611ef89190612ddf565b60008060006127a3858561258e565b9092509050600182016127bc5760001992505050611c4e565b6000806127ca846001612ddf565b905060005b8381101561282b576127e588612760848a612ddf565b9095509250600183016128015760001995505050505050611c4e565b8261280d866001612ddf565b6128179190612ddf565b6128219083612ddf565b91506001016127cf565b509695505050505050565b7f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c19930080546001600160a01b031981166001600160a01b03848116918217845560405192169182907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a3505050565b60008060006128b685856129ac565b9092509050600182016128cf5760001992505050611c4e565b806128db836025612ddf565b6128e59190612ddf565b611ef8906004612ddf565b6000611ccf8383016020015190565b60006020600083516020850160025afa50602060006020600060025afa5050600051919050565b600082828151811061293a5761293a612dae565b016020015160f81c60ff0361295157506008611c4e565b82828151811061296357612963612dae565b016020015160f81c60fe0361297a57506004611c4e565b82828151811061298c5761298c612dae565b016020015160f81c60fd036129a357506002611c4e565b50600092915050565b6000806129ba836025612ddf565b845110156129cf575060001990506000612729565b6000806129e186612760876024612ddf565b9097909650945050505050565b600060208284031215612a0057600080fd5b5035919050565b60008083601f840112612a1957600080fd5b5081356001600160401b03811115612a3057600080fd5b6020830191508360208260051b850101111561272957600080fd5b60008060008060408587031215612a6157600080fd5b84356001600160401b03811115612a7757600080fd5b612a8387828801612a07565b90955093505060208501356001600160401b03811115612aa257600080fd5b612aae87828801612a07565b95989497509550505050565b60008083601f840112612acc57600080fd5b5081356001600160401b03811115612ae357600080fd5b60208301915083602082850101111561272957600080fd5b600080600080600060608688031215612b1357600080fd5b85356001600160401b03811115612b2957600080fd5b612b3588828901612aba565b90965094505060208601356001600160401b03811115612b5457600080fd5b612b6088828901612aba565b96999598509660400135949350505050565b60005b83811015612b8d578181015183820152602001612b75565b50506000910152565b6020815260008251806020840152612bb5816040850160208701612b72565b601f01601f19169190910160400192915050565b60006101208284031215612bdc57600080fd5b50919050565b600060208284031215612bf457600080fd5b81356001600160401b03811115612c0a57600080fd5b612c1684828501612bc9565b949350505050565b600080600060608486031215612c3357600080fd5b83356001600160401b03811115612c4957600080fd5b612c5586828701612bc9565b9660208601359650604090950135949350505050565b80356001600160e01b031981168114612c8357600080fd5b919050565b60008060408385031215612c9b57600080fd5b82359150612cab60208401612c6b565b90509250929050565b600060208284031215612cc657600080fd5b81356001600160a01b0381168114611ccf57600080fd5b60008060208385031215612cf057600080fd5b82356001600160401b03811115612d0657600080fd5b612d1285828601612aba565b90969095509350505050565b60008060008060408587031215612d3457600080fd5b84356001600160401b03811115612d4a57600080fd5b612d5687828801612aba565b90955093505060208501356001600160401b03811115612d7557600080fd5b612aae87828801612aba565b634e487b7160e01b600052601160045260246000fd5b8082028115828204841417611c4e57611c4e612d81565b634e487b7160e01b600052603260045260246000fd5b600060208284031215612dd657600080fd5b611ccf82612c6b565b80820180821115611c4e57611c4e612d81565b835181526020938401516001600160e01b031916938101939093526040830191909152606082015260800190565b6020808252601e908201527f4465706f736974207363726970742063616e6e6f7420626520656d7074790000604082015260600190565b634e487b7160e01b600052604160045260246000fd5b600181811c90821680612e8157607f821691505b602082108103612bdc57634e487b7160e01b600052602260045260246000fd5b601f821115612eeb57806000526020600020601f840160051c81016020851015612ec85750805b601f840160051c820191505b81811015612ee85760008155600101612ed4565b50505b505050565b6001600160401b03831115612f0757612f07612e57565b612f1b83612f158354612e6d565b83612ea1565b6000601f841160018114612f4f5760008515612f375750838201355b600019600387901b1c1916600186901b178355612ee8565b600083815260209020601f19861690835b82811015612f805786850135825560209485019460019092019101612f60565b5086821015612f9d5760001960f88860031b161c19848701351681555b505060018560011b0183555050505050565b81835281816020850137506000828201602090810191909152601f909101601f19169091010190565b604081526000612fec604083018688612faf565b8281036020840152612fff818587612faf565b979650505050505050565b6000808335601e1984360301811261302157600080fd5b8301803591506001600160401b0382111561303b57600080fd5b60200191503681900382131561272957600080fd5b81810381811115611c4e57611c4e612d81565b60006001820161307557613075612d81565b5060010190565b602081526000612c16602083018486612faf565b6000602082840312156130a257600080fd5b81356001600160f01b031981168114611ccf57600080fd5b8581528460208201526080604082015260006130da608083018587612faf565b90508260608301529695505050505050565b6000602082840312156130fe57600080fd5b81518015158114611ccf57600080fd5b60208082526022908201527f52656164206f76657272756e20647572696e6720566172496e742070617273696040820152616e6760f01b606082015260800190565b6001600160e01b0319851681528351600090613173816004850160208901612b72565b84519083019061318a816004840160208901612b72565b6001600160e01b0319949094169301600481019390935250506008019392505050565b805160208201516bffffffffffffffffffffffff198116919060148210156131f9576bffffffffffffffffffffffff196bffffffffffffffffffffffff198360140360031b1b82161692505b5050919050565b6001600160e01b03198a1681526001600160f01b031989166004820152868860068301376000878201600681016000815287898237506000908701600601908152848682376001600160e01b031993909316929093019182525060040198975050505050505050565b60ff8181168382160190811115611c4e57611c4e612d8156")),
        0,
        HashMap::new()
    ));

    config.data.push(AccountData::new(
        address!("31ffffffffffffffffffffffffffffffffffffff"),
        U256::ZERO,
        Bytes::from_static(&hex!("60806040526004361061007b5760003560e01c80639623609d1161004e5780639623609d1461011157806399a88ec414610124578063f2fde38b14610144578063f3b7dead1461016457600080fd5b8063204e1c7a14610080578063715018a6146100bc5780637eff275e146100d35780638da5cb5b146100f3575b600080fd5b34801561008c57600080fd5b506100a061009b366004610499565b610184565b6040516001600160a01b03909116815260200160405180910390f35b3480156100c857600080fd5b506100d1610215565b005b3480156100df57600080fd5b506100d16100ee3660046104bd565b610229565b3480156100ff57600080fd5b506000546001600160a01b03166100a0565b6100d161011f36600461050c565b610291565b34801561013057600080fd5b506100d161013f3660046104bd565b610300565b34801561015057600080fd5b506100d161015f366004610499565b610336565b34801561017057600080fd5b506100a061017f366004610499565b6103b4565b6000806000836001600160a01b03166040516101aa90635c60da1b60e01b815260040190565b600060405180830381855afa9150503d80600081146101e5576040519150601f19603f3d011682016040523d82523d6000602084013e6101ea565b606091505b5091509150816101f957600080fd5b8080602001905181019061020d91906105ea565b949350505050565b61021d6103da565b6102276000610434565b565b6102316103da565b6040516308f2839760e41b81526001600160a01b038281166004830152831690638f283970906024015b600060405180830381600087803b15801561027557600080fd5b505af1158015610289573d6000803e3d6000fd5b505050505050565b6102996103da565b60405163278f794360e11b81526001600160a01b03841690634f1ef2869034906102c99086908690600401610607565b6000604051808303818588803b1580156102e257600080fd5b505af11580156102f6573d6000803e3d6000fd5b5050505050505050565b6103086103da565b604051631b2ce7f360e11b81526001600160a01b038281166004830152831690633659cfe69060240161025b565b61033e6103da565b6001600160a01b0381166103a85760405162461bcd60e51b815260206004820152602660248201527f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160448201526564647265737360d01b60648201526084015b60405180910390fd5b6103b181610434565b50565b6000806000836001600160a01b03166040516101aa906303e1469160e61b815260040190565b6000546001600160a01b031633146102275760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572604482015260640161039f565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b6001600160a01b03811681146103b157600080fd5b6000602082840312156104ab57600080fd5b81356104b681610484565b9392505050565b600080604083850312156104d057600080fd5b82356104db81610484565b915060208301356104eb81610484565b809150509250929050565b634e487b7160e01b600052604160045260246000fd5b60008060006060848603121561052157600080fd5b833561052c81610484565b9250602084013561053c81610484565b9150604084013567ffffffffffffffff81111561055857600080fd5b8401601f8101861361056957600080fd5b803567ffffffffffffffff811115610583576105836104f6565b604051601f8201601f19908116603f0116810167ffffffffffffffff811182821017156105b2576105b26104f6565b6040528181528282016020018810156105ca57600080fd5b816020840160208301376000602083830101528093505050509250925092565b6000602082840312156105fc57600080fd5b81516104b681610484565b60018060a01b0383168152604060208201526000825180604084015260005b818110156106435760208186018101516060868401015201610626565b506000606082850101526060601f19601f830116840101915050939250505056")),
        0,
        [
            (U256::from_be_slice(&hex!("0000000000000000000000000000000000000000000000000000000000000000")), U256::from_be_slice(&hex!("000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266")))
        ].into_iter().collect(),
    ));
}
