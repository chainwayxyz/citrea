use std::collections::HashMap;
use std::str::FromStr;

use alloy_primitives::LogData;
use reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT;
use reth_primitives::{address, b256, hex, BlockNumberOrTag, Log, TxKind};
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

    let (evm, mut working_set) = get_evm(&config);

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
                l1_diff_size: 437,
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
                l1_diff_size: 565,
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 392686,
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
                                vec![b256!("89ed79f38bee253aee2fb8d52df0d71b4aaf0843800d093a499a55eeca455c34")],
                                Bytes::from_static(&hex!("00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000b5d2205daf577048c5e5a9a75d0a924ed03e226c3304f4a2f01c65ca1dab73522e6b8bad206228eba653cf1819bcfc1bc858630e5ae373eec1a9924322a5fe8445c5e76027ad201521d65f64be3f71b71ca462220f13c77b251027f6ca443a483353a96fbce222ad200fabeed269694ee83d9b3343a571202e68af65d05feda61dbed0c4bdb256a6eaad2000326d6f721c03dc5f1d8817d8f8ee890a95a2eeda0d4d9a01b1cc9b7b1b724dac006306636974726561140000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0800000000000f42406800000000000000000000000000000000000000000000"))
                            ).unwrap(),
                        }
                    ]
                },
                gas_used: 261215,
                log_index_start: 1,
                l1_diff_size: 1013,
            }
        ]
    );

    let l1_fee_rate = 1;
    let l2_height = 2;

    let system_account = evm.accounts.get(&SYSTEM_SIGNER, &mut working_set).unwrap();
    // The system caller balance is unchanged(if exists)/or should be 0
    assert_eq!(system_account.info.balance, U256::from(0));
    assert_eq!(system_account.info.nonce, 3);

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
    assert_eq!(system_account.info.balance, U256::from(0));
    assert_eq!(system_account.info.nonce, 4);

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
                l1_diff_size: 565,
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
                l1_diff_size: 935,
            },
        ]
    );
    let base_fee_vault = evm.accounts.get(&BASE_FEE_VAULT, &mut working_set).unwrap();
    let l1_fee_vault = evm.accounts.get(&L1_FEE_VAULT, &mut working_set).unwrap();

    assert_eq!(
        base_fee_vault.info.balance,
        U256::from(114235u64 * 10000000)
    );
    assert_eq!(l1_fee_vault.info.balance, U256::from(935));

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

    let (evm, mut working_set) = get_evm(&config);
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

    let (evm, mut working_set) = get_evm(&config);

    let l1_fee_rate = 1;
    let l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_height: 2,
        da_slot_hash: [2u8; 32],
        da_slot_txs_commitment: [
            136, 147, 225, 201, 35, 145, 64, 167, 182, 140, 185, 55, 22, 224, 150, 42, 51, 86, 214,
            251, 181, 122, 169, 246, 188, 29, 186, 32, 227, 33, 199, 38,
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
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 128, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 42, 1, 196, 196, 205, 156, 93, 62, 54, 134, 133, 188, 6, 17, 153, 42,
            62, 155, 138, 8, 111, 222, 48, 192, 86, 41, 210, 202, 111, 100, 49, 6, 36, 123, 0, 0,
            0, 0, 0, 253, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 87, 2, 197, 63, 15, 0, 0, 0, 0, 0, 34, 81, 32, 225, 85, 228, 181, 8,
            114, 26, 130, 4, 159, 125, 249, 18, 119, 121, 134, 147, 142, 99, 173, 85, 230, 58, 42,
            39, 210, 102, 158, 156, 54, 47, 183, 74, 1, 0, 0, 0, 0, 0, 0, 34, 0, 32, 74, 232, 21,
            114, 240, 110, 27, 136, 253, 92, 237, 122, 26, 0, 9, 69, 67, 46, 131, 225, 85, 30, 111,
            114, 30, 233, 192, 11, 140, 195, 50, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 91, 7, 64,
            85, 100, 226, 121, 160, 231, 130, 160, 201, 56, 39, 35, 161, 143, 216, 21, 211, 206,
            127, 229, 78, 29, 6, 86, 241, 85, 191, 62, 174, 148, 71, 7, 97, 25, 170, 78, 173, 238,
            251, 184, 7, 3, 139, 103, 184, 9, 84, 28, 37, 39, 39, 91, 248, 166, 240, 149, 245, 51,
            48, 45, 10, 151, 90, 134, 64, 58, 4, 251, 18, 243, 51, 241, 78, 218, 137, 248, 84, 193,
            73, 6, 249, 29, 144, 62, 120, 43, 235, 170, 173, 3, 241, 236, 171, 253, 71, 17, 237,
            81, 214, 38, 47, 206, 119, 2, 116, 56, 203, 107, 84, 255, 102, 133, 42, 245, 35, 173,
            250, 41, 110, 193, 18, 121, 214, 157, 81, 81, 115, 91, 237, 64, 21, 17, 223, 104, 155,
            182, 45, 200, 209, 237, 114, 78, 88, 157, 251, 106, 70, 76, 150, 27, 223, 254, 87, 62,
            121, 250, 18, 141, 166, 53, 181, 63, 41, 28, 81, 51, 20, 84, 115, 122, 154, 139, 187,
            182, 208, 212, 16, 122, 183, 103, 149, 223, 86, 216, 191, 246, 117, 102, 59, 111, 120,
            22, 223, 62, 64, 253, 145, 239, 196, 249, 255, 135, 5, 208, 64, 144, 150, 213, 166, 66,
            98, 4, 23, 151, 165, 220, 201, 209, 179, 201, 162, 185, 98, 0, 228, 44, 29, 230, 117,
            232, 11, 123, 162, 71, 201, 73, 125, 209, 236, 189, 139, 56, 160, 205, 48, 238, 29,
            185, 43, 229, 103, 117, 247, 252, 85, 166, 29, 59, 232, 64, 189, 1, 191, 87, 25, 32,
            77, 193, 98, 33, 84, 159, 168, 209, 181, 157, 80, 130, 164, 59, 101, 196, 190, 247,
            124, 131, 53, 156, 111, 105, 196, 18, 8, 177, 1, 118, 217, 178, 150, 165, 172, 205,
            126, 106, 54, 246, 54, 95, 47, 16, 155, 156, 123, 135, 135, 4, 44, 241, 144, 188, 76,
            181, 157, 173, 210, 32, 93, 175, 87, 112, 72, 197, 229, 169, 167, 93, 10, 146, 78, 208,
            62, 34, 108, 51, 4, 244, 162, 240, 28, 101, 202, 29, 171, 115, 82, 46, 107, 139, 173,
            32, 98, 40, 235, 166, 83, 207, 24, 25, 188, 252, 27, 200, 88, 99, 14, 90, 227, 115,
            238, 193, 169, 146, 67, 34, 165, 254, 132, 69, 197, 231, 96, 39, 173, 32, 21, 33, 214,
            95, 100, 190, 63, 113, 183, 28, 164, 98, 34, 15, 19, 199, 123, 37, 16, 39, 246, 202,
            68, 58, 72, 51, 83, 169, 111, 188, 226, 34, 173, 32, 15, 171, 238, 210, 105, 105, 78,
            232, 61, 155, 51, 67, 165, 113, 32, 46, 104, 175, 101, 208, 95, 237, 166, 29, 190, 208,
            196, 189, 178, 86, 166, 234, 173, 32, 0, 50, 109, 111, 114, 28, 3, 220, 95, 29, 136,
            23, 216, 248, 238, 137, 10, 149, 162, 238, 218, 13, 77, 154, 1, 177, 204, 155, 123, 27,
            114, 77, 172, 0, 99, 6, 99, 105, 116, 114, 101, 97, 20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 8, 0, 0, 0, 0, 0, 15, 66, 64, 104, 65, 193, 147, 199, 55,
            141, 150, 81, 138, 117, 68, 136, 33, 196, 247, 200, 244, 186, 231, 206, 96, 248, 4,
            208, 61, 31, 6, 40, 221, 93, 208, 245, 222, 81, 15, 41, 81, 255, 251, 84, 130, 89, 213,
            171, 185, 243, 81, 190, 143, 148, 3, 28, 156, 232, 140, 232, 56, 180, 13, 124, 236,
            124, 96, 110, 12, 122, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
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
        recipient_account.info.balance,
        U256::from_str("0x2386f26fc10000").unwrap(),
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

    let (evm, mut working_set) = get_evm(&config);

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

    let (evm, mut working_set) = get_evm(&config);

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
        Bytes::from_static(&hex!("608060405234801561001057600080fd5b50600436106100a95760003560e01c806357e871e71161007157806357e871e71461014c57806361b207e214610155578063a91d8b3d14610182578063d269a03e146101a2578063d761753e146101b5578063ee82ac5e146101e857600080fd5b80630466efc4146100ae5780630e27bc11146100e15780631f578333146100f657806334cdf78d146101095780634ffd344a14610129575b600080fd5b6100ce6100bc366004610599565b60009081526002602052604090205490565b6040519081526020015b60405180910390f35b6100f46100ef3660046105b2565b610208565b005b6100f4610104366004610599565b610331565b6100ce610117366004610599565b60016020526000908152604090205481565b61013c61013736600461061d565b6103df565b60405190151581526020016100d8565b6100ce60005481565b6100ce610163366004610599565b6000908152600160209081526040808320548352600290915290205490565b6100ce610190366004610599565b60026020526000908152604090205481565b61013c6101b036600461061d565b610405565b6101d073deaddeaddeaddeaddeaddeaddeaddeaddeaddead81565b6040516001600160a01b0390911681526020016100d8565b6100ce6101f6366004610599565b60009081526001602052604090205490565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146102705760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c65720060448201526064015b60405180910390fd5b60008054908190036102b65760405162461bcd60e51b815260206004820152600f60248201526e139bdd081a5b9a5d1a585b1a5e9959608a1b6044820152606401610267565b60008181526001602081905260409091208490556102d5908290610678565b6000908155838152600260209081526040808320859055915482519081529081018590529081018390527f32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f9060600160405180910390a1505050565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146103945760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c6572006044820152606401610267565b600054156103da5760405162461bcd60e51b8152602060048201526013602482015272105b1c9958591e481a5b9a5d1a585b1a5e9959606a1b6044820152606401610267565b600055565b6000858152600160205260408120546103fb9086868686610410565b9695505050505050565b60006103fb86868686865b6000858152600260209081526040808320548151601f870184900484028101840190925285825291610463918891849190899089908190840183828082843760009201919091525089925061046e915050565b979650505050505050565b6000838514801561047d575081155b801561048857508251155b15610495575060016104a4565b6104a1858486856104ac565b90505b949350505050565b6000602084516104bc9190610699565b156104c9575060006104a4565b83516000036104da575060006104a4565b818560005b8651811015610549576104f3600284610699565b6001036105175761051061050a8883016020015190565b83610556565b9150610530565b61052d826105288984016020015190565b610556565b91505b60019290921c91610542602082610678565b90506104df565b5090931495945050505050565b6000610562838361056b565b90505b92915050565b60008260005281602052602060006040600060025afa50602060006020600060025afa505060005192915050565b6000602082840312156105ab57600080fd5b5035919050565b600080604083850312156105c557600080fd5b50508035926020909101359150565b60008083601f8401126105e657600080fd5b50813567ffffffffffffffff8111156105fe57600080fd5b60208301915083602082850101111561061657600080fd5b9250929050565b60008060008060006080868803121561063557600080fd5b8535945060208601359350604086013567ffffffffffffffff81111561065a57600080fd5b610666888289016105d4565b96999598509660600135949350505050565b8082018082111561056557634e487b7160e01b600052601160045260246000fd5b6000826106b657634e487b7160e01b600052601260045260246000fd5b50069056")),
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
        Bytes::from_static(&hex!("60806040526004361061019c5760003560e01c80638786dba7116100ec578063d761753e1161008a578063e613ae0011610064578063e613ae0014610489578063f119a9bd146104a4578063f2fde38b146104c4578063f8e655d2146104e457600080fd5b8063d761753e1461042c578063dd95c7c614610454578063e30c39781461047457600080fd5b8063a41c5cf3116100c6578063a41c5cf3146103aa578063b3ab15fb146103bf578063bafa9eb2146103df578063c045577b146103ff57600080fd5b80638786dba71461036d57806387f8bf56146103805780638da5cb5b1461039557600080fd5b8063570ca73511610159578063715018a611610133578063715018a61461030e57806374ab4a8314610323578063781952a81461034357806379ba50971461035857600080fd5b8063570ca735146102945780635d3e3176146102cc5780635e3cc740146102ee57600080fd5b806311e53a01146101a1578063158ef93e146101e1578063198546231461020b5780634126013714610220578063419759f514610240578063471ba1e314610256575b600080fd5b3480156101ad57600080fd5b506101ce6101bc36600461296a565b60066020526000908152604090205481565b6040519081526020015b60405180910390f35b3480156101ed57600080fd5b506000546101fb9060ff1681565b60405190151581526020016101d8565b61021e6102193660046129c7565b610504565b005b34801561022c57600080fd5b5061021e61023b366004612a77565b6106dd565b34801561024c57600080fd5b506101ce60015481565b34801561026257600080fd5b5061027661027136600461296a565b6108da565b604080519283526001600160e01b03199091166020830152016101d8565b3480156102a057600080fd5b506002546102b4906001600160a01b031681565b6040516001600160a01b0390911681526020016101d8565b3480156102d857600080fd5b506102e161090b565b6040516101d89190612b12565b3480156102fa57600080fd5b5061021e610309366004612b5e565b610999565b34801561031a57600080fd5b5061021e610cf4565b34801561032f57600080fd5b5061021e61033e366004612b9a565b610d08565b34801561034f57600080fd5b506027546101ce565b34801561036457600080fd5b5061021e610edb565b61021e61037b366004612c04565b610f23565b34801561038c57600080fd5b506102e161104a565b3480156103a157600080fd5b506102b4611057565b3480156103b657600080fd5b506102e161108c565b3480156103cb57600080fd5b5061021e6103da366004612c30565b611099565b3480156103eb57600080fd5b506101fb6103fa36600461296a565b6110fc565b34801561040b57600080fd5b506101ce61041a36600461296a565b60286020526000908152604090205481565b34801561043857600080fd5b506102b473deaddeaddeaddeaddeaddeaddeaddeaddeaddead81565b34801561046057600080fd5b5061021e61046f366004612b5e565b611127565b34801561048057600080fd5b506102b4611582565b34801561049557600080fd5b506102b46001603160981b0181565b3480156104b057600080fd5b5061021e6104bf366004612c59565b6115ab565b3480156104d057600080fd5b5061021e6104df366004612c30565b61161f565b3480156104f057600080fd5b5061021e6104ff366004612c9a565b6116a4565b82811461054a5760405162461bcd60e51b815260206004820152600f60248201526e098cadccee8d040dad2e6dac2e8c6d608b1b60448201526064015b60405180910390fd5b600154610558908490612d13565b34146105a05760405162461bcd60e51b8152602060048201526017602482015276125b9d985b1a59081dda5d1a191c985dc8185b5bdd5b9d604a1b6044820152606401610541565b60275460005b848110156106d557600060405180604001604052808888858181106105cd576105cd612d2a565b9050602002013581526020018686858181106105eb576105eb612d2a565b90506020020160208101906106009190612d40565b6001600160e01b03191690526027805460018101825560009190915281517f98a476f1687bc3d60a2da2adbcba2c46958e61fa2fb4042cd7bc5816a710195b60029092029182015560208201517f98a476f1687bc3d60a2da2adbcba2c46958e61fa2fb4042cd7bc5816a710195c909101805463ffffffff191660e09290921c91909117905590507f3311a04a346a103ac115cca33028a2bc82f1964805860d0d3fc84a2772496ada816106b48486612d5b565b426040516106c493929190612d6e565b60405180910390a1506001016105a6565b505050505050565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146107405760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c6572006044820152606401610541565b60005460ff16156107935760405162461bcd60e51b815260206004820152601f60248201527f436f6e747261637420697320616c726561647920696e697469616c697a6564006044820152606401610541565b806000036107e35760405162461bcd60e51b815260206004820152601a60248201527f4465706f73697420616d6f756e742063616e6e6f7420626520300000000000006044820152606401610541565b60008490036108045760405162461bcd60e51b815260040161054190612d9c565b6000805460ff19166001179055600361081e858783612e6c565b50600461082c838583612e6c565b506001819055600280546001600160a01b03191673deaddeaddeaddeaddeaddeaddeaddeaddeaddead908117909155604080516000815260208101929092527ffbe5b6cbafb274f445d7fed869dc77a838d8243a22c460de156560e8857cad03910160405180910390a17f80bd1fdfe157286ce420ee763f91748455b249605748e5df12dad9844402bafc858585856040516108cb9493929190612f54565b60405180910390a15050505050565b602781815481106108ea57600080fd5b60009182526020909120600290910201805460019091015490915060e01b82565b6029805461091890612de9565b80601f016020809104026020016040519081016040528092919081815260200182805461094490612de9565b80156109915780601f1061096657610100808354040283529160200191610991565b820191906000526020600020905b81548152906001019060200180831161097457829003601f168201915b505050505081565b6109a28161171e565b50600090506109f16109b76060840184612f86565b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250611a4192505050565b915060009050610a4e610a076060850185612f86565b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250610a49925060019150869050612fcc565b611a58565b90506000610a5b82611bd0565b90506000610a73610a6e83836020611c52565b611d15565b90506000610a94610a6e6020808651610a8c9190612fcc565b869190611c52565b600083815260066020526040812054919250610af0610ab660808a018a612f86565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201829052509250611d9a915050565b90506000610aff826001611e7d565b9050600060298054610b1090612de9565b915060009050610b21838284611c52565b9050610bb78160298054610b3490612de9565b80601f0160208091040260200160405190810160405280929190818152602001828054610b6090612de9565b8015610bad5780601f10610b8257610100808354040283529160200191610bad565b820191906000526020600020905b815481529060010190602001808311610b9057829003601f168201915b5050505050612001565b610c035760405162461bcd60e51b815260206004820152601a60248201527f496e76616c696420736c6173684f7254616b65207363726970740000000000006044820152606401610541565b60008581526028602052604081205490811580610c285750610c24886120d8565b8214155b905080610c775760405162461bcd60e51b815260206004820152601960248201527f4f70657261746f72206973206e6f74206d616c6963696f7573000000000000006044820152606401610541565b60016007896103e88110610c8d57610c8d612d2a565b602091828204019190066101000a81548160ff0219169083151502179055507ff918cdaebea74c5a8c3b02d7404c162f507551b158202cedcba9b6a74eabdff288604051610cdd91815260200190565b60405180910390a150505050505050505050505050565b610cfc6120e5565b610d066000612117565b565b610d118361171e565b5060009050610d62610d266040860186612f86565b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250879250612153915050565b90506000610d6f826122a6565b90506000610d7c836122b3565b9050600060278581548110610d9357610d93612d2a565b60009182526020918290206040805180820190915260029290920201805480835260019091015460e01b6001600160e01b03191692820192909252915083148015610df55750816001600160e01b03191681602001516001600160e01b031916145b610e355760405162461bcd60e51b81526020600482015260116024820152706e6f74206d61746368696e67205554584f60781b6044820152606401610541565b6000610e476109b760608a018a612f86565b915060009050610e5d610a0760608b018b612f86565b90506000610e6a82611bd0565b90506000610e7782611d15565b9050610e82816120d8565b60008a8152602860209081526040918290209290925580518b81529182018390527feedf47c2f61b040827944fd45e44ef6d742354b34e1af7dd99a56f444ec79347910160405180910390a15050505050505050505050565b3380610ee5611582565b6001600160a01b031614610f175760405163118cdaa760e01b81526001600160a01b0382166004820152602401610541565b610f2081612117565b50565b6001543414610f6e5760405162461bcd60e51b8152602060048201526017602482015276125b9d985b1a59081dda5d1a191c985dc8185b5bdd5b9d604a1b6044820152606401610541565b6040805180820182528381526001600160e01b03198316602082019081526027805460018101825560009190915282517f98a476f1687bc3d60a2da2adbcba2c46958e61fa2fb4042cd7bc5816a710195b600283029081019190915591517f98a476f1687bc3d60a2da2adbcba2c46958e61fa2fb4042cd7bc5816a710195c909201805463ffffffff191660e09390931c9290921790915591519091907f3311a04a346a103ac115cca33028a2bc82f1964805860d0d3fc84a2772496ada9061103c90849084904290612d6e565b60405180910390a150505050565b6004805461091890612de9565b6000807f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c1993005b546001600160a01b031692915050565b6003805461091890612de9565b6110a16120e5565b600280546001600160a01b0319166001600160a01b0383169081179091556040805182815260208101929092527ffbe5b6cbafb274f445d7fed869dc77a838d8243a22c460de156560e8857cad03910160405180910390a150565b6007816103e8811061110d57600080fd5b60209182820401919006915054906101000a900460ff1681565b6002546001600160a01b031633146111815760405162461bcd60e51b815260206004820152601a60248201527f63616c6c6572206973206e6f7420746865206f70657261746f720000000000006044820152606401610541565b60008061118d8361171e565b91509150806001146111da5760405162461bcd60e51b815260206004820152601660248201527513db9b1e481bdb99481a5b9c1d5d08185b1b1bddd95960521b6044820152606401610541565b60006112856111ec6020860186612d40565b6111f96040870187612f86565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525061123b925050506060880188612f86565b8080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506112809250505060c0890160a08a01612d40565b6122c0565b600081815260066020526040902054909150156112d95760405162461bcd60e51b81526020600482015260126024820152711d1e125908185b1c9958591e481cdc195b9d60721b6044820152606401610541565b6005600081546112e890612fdf565b918290555060008281526006602052604081209190915561130f610ab66080870187612f86565b9050600061131c82611a41565b915050806003146113675760405162461bcd60e51b8152602060048201526015602482015274496e76616c6964207769746e657373206974656d7360581b6044820152606401610541565b6000611374836001611e7d565b905060006003805461138590612de9565b915060009050611396838284611c52565b90506113a98160038054610b3490612de9565b6113ee5760405162461bcd60e51b8152602060048201526016602482015275125b9d985b1a590819195c1bdcda5d081cd8dc9a5c1d60521b6044820152606401610541565b60006114226004805461140090612de9565b865161140c9250612fcc565b6004805461141990612de9565b87929150611c52565b90506114358160048054610b3490612de9565b6114795760405162461bcd60e51b8152602060048201526015602482015274092dcecc2d8d2c840e6c6e4d2e0e840e6eaccccd2f605b1b6044820152606401610541565b6000611484856122f0565b600554604080518d8152602081018c90526001600160a01b038416818301524260608201526080810192909252519192507fa82453ca34121b3ecb910d957824e27c5dc6465315949facd15fb72886490058919081900360a00190a16001546040516000916001600160a01b038416918381818185875af1925050503d806000811461152c576040519150601f19603f3d011682016040523d82523d6000602084013e611531565b606091505b50509050806115745760405162461bcd60e51b815260206004820152600f60248201526e151c985b9cd9995c8819985a5b1959608a1b6044820152606401610541565b505050505050505050505050565b6000807f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c0061107c565b6115b36120e5565b60008190036115d45760405162461bcd60e51b815260040161054190612d9c565b60296115e1828483612e6c565b507f8578c80bdea3ff51431011ed88db9cb415de2cf64f9ed5e7137288268cbdeb2c8282604051611613929190612ff8565b60405180910390a15050565b6116276120e5565b7f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c0080546001600160a01b0319166001600160a01b038316908117825561166b611057565b6001600160a01b03167f38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e2270060405160405180910390a35050565b6116ac6120e5565b60008390036116cd5760405162461bcd60e51b815260040161054190612d9c565b60036116da848683612e6c565b5060046116e8828483612e6c565b507f80bd1fdfe157286ce420ee763f91748455b249605748e5df12dad9844402bafc8484848460405161103c9493929190612f54565b6000808061177e6117326020860186612d40565b611742604087016020880161300c565b61174f6040880188612f86565b61175c60608a018a612f86565b61176960808c018c612f86565b61177960c08e0160a08f01612d40565b612326565b90506117ca6117906040860186612f86565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525061235a92505050565b6118165760405162461bcd60e51b815260206004820152601d60248201527f56696e206973206e6f742070726f7065726c7920666f726d61747465640000006044820152606401610541565b6118606118266060860186612f86565b8080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506123fe92505050565b6118ac5760405162461bcd60e51b815260206004820152601e60248201527f566f7574206973206e6f742070726f7065726c7920666f726d617474656400006044820152606401610541565b60006118be6109b76040870187612f86565b915061190e90506118d26080870187612f86565b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250859250612495915050565b6119645760405162461bcd60e51b815260206004820152602160248201527f5769746e657373206973206e6f742070726f7065726c7920666f726d617474656044820152601960fa1b6064820152608401610541565b6001603160981b01634ffd344a60e08701358461198460c08a018a612f86565b8a61010001356040518663ffffffff1660e01b81526004016119aa959493929190613036565b602060405180830381865afa1580156119c7573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906119eb9190613068565b611a375760405162461bcd60e51b815260206004820152601b60248201527f5472616e73616374696f6e206973206e6f7420696e20626c6f636b00000000006044820152606401610541565b9094909350915050565b600080611a4f83600061250a565b91509150915091565b6060600080611a6685611a41565b909250905060018201611a8b5760405162461bcd60e51b81526004016105419061308a565b808410611ace5760405162461bcd60e51b81526020600482015260116024820152702b37baba103932b0b21037bb32b9393ab760791b6044820152606401610541565b600080611adc846001612d5b565b905060005b86811015611b5a57611af388836126ac565b92506000198303611b465760405162461bcd60e51b815260206004820152601a60248201527f42616420566172496e7420696e207363726970745075626b65790000000000006044820152606401610541565b611b508383612d5b565b9150600101611ae1565b50611b6587826126ac565b91506000198203611bb85760405162461bcd60e51b815260206004820152601a60248201527f42616420566172496e7420696e207363726970745075626b65790000000000006044820152606401610541565b611bc3878284611c52565b9450505050505b92915050565b606081600981518110611be557611be5612d2a565b6020910101516001600160f81b031916603560f91b14611c1357505060408051602081019091526000815290565b600082600a81518110611c2857611c28612d2a565b01602001516001600160f81b031981169150611c4b908490600b9060f81c611c52565b9392505050565b606081600003611c715750604080516020810190915260008152611c4b565b6000611c7d8385612d5b565b90508381118015611c8f575080855110155b611cd15760405162461bcd60e51b8152602060048201526013602482015272536c696365206f7574206f6620626f756e647360681b6044820152606401610541565b604051915082604083010160405282825283850182038460208701018481015b80821015611d0a57815183830152602082019150611cf1565b505050509392505050565b60008151600003611d2857506000919050565b81516020811115611d865760405162461bcd60e51b815260206004820152602260248201527f42797465732063616e6e6f74206265206d6f7265207468616e20333220627974604482015261657360f01b6064820152608401610541565b60209283015192036008029190911c919050565b606060008060005b84811015611e1357611db48683612710565b92506000198303611dff5760405162461bcd60e51b815260206004820152601560248201527442616420566172496e7420696e207769746e65737360581b6044820152606401610541565b611e098383612d5b565b9150600101611da2565b50611e1e8582612710565b91506000198203611e695760405162461bcd60e51b815260206004820152601560248201527442616420566172496e7420696e207769746e65737360581b6044820152606401610541565b611e74858284611c52565b95945050505050565b6060600080611e8b85611a41565b909250905060018201611eb05760405162461bcd60e51b81526004016105419061308a565b808410611ef25760405162461bcd60e51b815260206004820152601060248201526f2b34b7103932b0b21037bb32b9393ab760811b6044820152606401610541565b600080611f00846001612d5b565b905060005b86811015611f8b57611f17888361250a565b909550925060018301611f615760405162461bcd60e51b815260206004820152601260248201527142616420566172496e7420696e206974656d60701b6044820152606401610541565b82611f6d866001612d5b565b611f779190612d5b565b611f819083612d5b565b9150600101611f05565b50611f96878261250a565b909450915060018201611fe05760405162461bcd60e51b815260206004820152601260248201527142616420566172496e7420696e206974656d60701b6044820152606401610541565b611bc381611fee8685612d5b565b611ff9906001612d5b565b899190611c52565b81518151600091908114612019576000915050611bca565b60206000805b83831161204f575050848101518482015160209092019180821461204a576000945050505050611bca565b61201f565b600061205c602085612fcc565b90505b848110156120ca5786818151811061207957612079612d2a565b602001015160f81c60f81b6001600160f81b0319168882815181106120a0576120a0612d2a565b01602001516001600160f81b031916146120c257600095505050505050611bca565b60010161205f565b506001979650505050505050565b6000611bca826001612d5b565b336120ee611057565b6001600160a01b031614610d065760405163118cdaa760e01b8152336004820152602401610541565b7f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c0080546001600160a01b031916815561214f826127b2565b5050565b606060008061216185611a41565b9092509050600182016121865760405162461bcd60e51b81526004016105419061308a565b8084106121c85760405162461bcd60e51b815260206004820152601060248201526f2b34b7103932b0b21037bb32b9393ab760811b6044820152606401610541565b6000806121d6846001612d5b565b905060005b8681101561224e576121ed8883612823565b9250600019830361223a5760405162461bcd60e51b815260206004820152601760248201527642616420566172496e7420696e2073637269707453696760481b6044820152606401610541565b6122448383612d5b565b91506001016121db565b506122598782612823565b91506000198203611bb85760405162461bcd60e51b815260206004820152601760248201527642616420566172496e7420696e2073637269707453696760481b6044820152606401610541565b6020810151600090611bca565b6000611bca82602061286c565b6000611e74858585856040516020016122dc94939291906130cc565b60405160208183030381529060405261287b565b6000806003805461230090612de9565b91506000905061231284836014611c52565b61231b90613129565b60601c949350505050565b600061234c8a8a8a8a8a8a8a8a8a6040516020016122dc9998979695949392919061317c565b9a9950505050505050505050565b600080600061236884611a41565b909250905080158061237b575060001982145b1561238a575060009392505050565b6000612397836001612d5b565b905060005b828110156123f157855182106123b85750600095945050505050565b60006123c48784612823565b905060001981036123dc575060009695505050505050565b6123e68184612d5b565b92505060010161239c565b5093519093149392505050565b600080600061240c84611a41565b909250905080158061241f575060001982145b1561242e575060009392505050565b600061243b836001612d5b565b905060005b828110156123f1578551821061245c5750600095945050505050565b600061246887846126ac565b90506000198103612480575060009695505050505050565b61248a8184612d5b565b925050600101612440565b6000816000036124a757506000611bca565b6000805b838110156124fe57845182106124c657600092505050611bca565b60006124d28684612710565b905060001981036124e95760009350505050611bca565b6124f38184612d5b565b9250506001016124ab565b50835114905092915050565b600080600061251985856128a2565b90508060ff1660000361254e57600085858151811061253a5761253a612d2a565b016020015190935060f81c91506126a59050565b8361255a8260016131e5565b60ff166125679190612d5b565b8551101561257e57600019600092509250506126a5565b60008160ff166002036125c2576125b76125a361259c876001612d5b565b889061286c565b62ffff0060e882901c1660f89190911c1790565b61ffff16905061269b565b8160ff16600403612611576126046125de61259c876001612d5b565b60d881901c63ff00ff001662ff00ff60e89290921c9190911617601081811b91901c1790565b63ffffffff16905061269b565b8160ff1660080361269b5761268f61262d61259c876001612d5b565b60c01c64ff000000ff600882811c91821665ff000000ff009390911b92831617601090811b6001600160401b031666ff00ff00ff00ff9290921667ff00ff00ff00ff009093169290921790911c65ffff0000ffff1617602081811c91901b1790565b6001600160401b031690505b60ff909116925090505b9250929050565b60006126b9826009612d5b565b835110156126ca5750600019611bca565b6000806126e1856126dc866008612d5b565b61250a565b9092509050600182016126fa5760001992505050611bca565b80612706836009612d5b565b611e749190612d5b565b600080600061271f858561250a565b9092509050600182016127385760001992505050611bca565b600080612746846001612d5b565b905060005b838110156127a757612761886126dc848a612d5b565b90955092506001830161277d5760001995505050505050611bca565b82612789866001612d5b565b6127939190612d5b565b61279d9083612d5b565b915060010161274b565b509695505050505050565b7f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c19930080546001600160a01b031981166001600160a01b03848116918217845560405192169182907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a3505050565b60008060006128328585612928565b90925090506001820161284b5760001992505050611bca565b80612857836025612d5b565b6128619190612d5b565b611e74906004612d5b565b6000611c4b8383016020015190565b60006020600083516020850160025afa50602060006020600060025afa5050600051919050565b60008282815181106128b6576128b6612d2a565b016020015160f81c60ff036128cd57506008611bca565b8282815181106128df576128df612d2a565b016020015160f81c60fe036128f657506004611bca565b82828151811061290857612908612d2a565b016020015160f81c60fd0361291f57506002611bca565b50600092915050565b600080612936836025612d5b565b8451101561294b5750600019905060006126a5565b60008061295d866126dc876024612d5b565b9097909650945050505050565b60006020828403121561297c57600080fd5b5035919050565b60008083601f84011261299557600080fd5b5081356001600160401b038111156129ac57600080fd5b6020830191508360208260051b85010111156126a557600080fd5b600080600080604085870312156129dd57600080fd5b84356001600160401b038111156129f357600080fd5b6129ff87828801612983565b90955093505060208501356001600160401b03811115612a1e57600080fd5b612a2a87828801612983565b95989497509550505050565b60008083601f840112612a4857600080fd5b5081356001600160401b03811115612a5f57600080fd5b6020830191508360208285010111156126a557600080fd5b600080600080600060608688031215612a8f57600080fd5b85356001600160401b03811115612aa557600080fd5b612ab188828901612a36565b90965094505060208601356001600160401b03811115612ad057600080fd5b612adc88828901612a36565b96999598509660400135949350505050565b60005b83811015612b09578181015183820152602001612af1565b50506000910152565b6020815260008251806020840152612b31816040850160208701612aee565b601f01601f19169190910160400192915050565b60006101208284031215612b5857600080fd5b50919050565b600060208284031215612b7057600080fd5b81356001600160401b03811115612b8657600080fd5b612b9284828501612b45565b949350505050565b600080600060608486031215612baf57600080fd5b83356001600160401b03811115612bc557600080fd5b612bd186828701612b45565b9660208601359650604090950135949350505050565b80356001600160e01b031981168114612bff57600080fd5b919050565b60008060408385031215612c1757600080fd5b82359150612c2760208401612be7565b90509250929050565b600060208284031215612c4257600080fd5b81356001600160a01b0381168114611c4b57600080fd5b60008060208385031215612c6c57600080fd5b82356001600160401b03811115612c8257600080fd5b612c8e85828601612a36565b90969095509350505050565b60008060008060408587031215612cb057600080fd5b84356001600160401b03811115612cc657600080fd5b612cd287828801612a36565b90955093505060208501356001600160401b03811115612cf157600080fd5b612a2a87828801612a36565b634e487b7160e01b600052601160045260246000fd5b8082028115828204841417611bca57611bca612cfd565b634e487b7160e01b600052603260045260246000fd5b600060208284031215612d5257600080fd5b611c4b82612be7565b80820180821115611bca57611bca612cfd565b835181526020938401516001600160e01b031916938101939093526040830191909152606082015260800190565b6020808252601e908201527f4465706f736974207363726970742063616e6e6f7420626520656d7074790000604082015260600190565b634e487b7160e01b600052604160045260246000fd5b600181811c90821680612dfd57607f821691505b602082108103612b5857634e487b7160e01b600052602260045260246000fd5b601f821115612e6757806000526020600020601f840160051c81016020851015612e445750805b601f840160051c820191505b81811015612e645760008155600101612e50565b50505b505050565b6001600160401b03831115612e8357612e83612dd3565b612e9783612e918354612de9565b83612e1d565b6000601f841160018114612ecb5760008515612eb35750838201355b600019600387901b1c1916600186901b178355612e64565b600083815260209020601f19861690835b82811015612efc5786850135825560209485019460019092019101612edc565b5086821015612f195760001960f88860031b161c19848701351681555b505060018560011b0183555050505050565b81835281816020850137506000828201602090810191909152601f909101601f19169091010190565b604081526000612f68604083018688612f2b565b8281036020840152612f7b818587612f2b565b979650505050505050565b6000808335601e19843603018112612f9d57600080fd5b8301803591506001600160401b03821115612fb757600080fd5b6020019150368190038213156126a557600080fd5b81810381811115611bca57611bca612cfd565b600060018201612ff157612ff1612cfd565b5060010190565b602081526000612b92602083018486612f2b565b60006020828403121561301e57600080fd5b81356001600160f01b031981168114611c4b57600080fd5b858152846020820152608060408201526000613056608083018587612f2b565b90508260608301529695505050505050565b60006020828403121561307a57600080fd5b81518015158114611c4b57600080fd5b60208082526022908201527f52656164206f76657272756e20647572696e6720566172496e742070617273696040820152616e6760f01b606082015260800190565b6001600160e01b03198516815283516000906130ef816004850160208901612aee565b845190830190613106816004840160208901612aee565b6001600160e01b0319949094169301600481019390935250506008019392505050565b805160208201516bffffffffffffffffffffffff19811691906014821015613175576bffffffffffffffffffffffff196bffffffffffffffffffffffff198360140360031b1b82161692505b5050919050565b6001600160e01b03198a1681526001600160f01b031989166004820152868860068301376000878201600681016000815287898237506000908701600601908152848682376001600160e01b031993909316929093019182525060040198975050505050505050565b60ff8181168382160190811115611bca57611bca612cfd56")),
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
