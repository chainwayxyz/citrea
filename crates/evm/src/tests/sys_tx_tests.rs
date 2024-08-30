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
                l1_diff_size: 288,
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
                l1_diff_size: 432,
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
                l1_diff_size: 936,
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
                l1_diff_size: 432,
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
                l1_diff_size: 701,
            },
        ]
    );
    let base_fee_vault = evm.accounts.get(&BASE_FEE_VAULT, &mut working_set).unwrap();
    let l1_fee_vault = evm.accounts.get(&L1_FEE_VAULT, &mut working_set).unwrap();

    assert_eq!(
        base_fee_vault.info.balance,
        U256::from(114235u64 * 10000000)
    );
    assert_eq!(l1_fee_vault.info.balance, U256::from(701 + L1_FEE_OVERHEAD));

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
        Bytes::from_static(&hex!("6080604052600436106101355760003560e01c80638e19899e116100ab578063d761753e1161006f578063d761753e1461032d578063dd95c7c614610355578063e30c397814610375578063e613ae001461038a578063ec6925a7146103a5578063f2fde38b146103c057600080fd5b80638e19899e146102a55780639f963f59146102b8578063b3ab15fb146102d8578063b93780f6146102f8578063d1c444561461030d57600080fd5b80635e0e5b3e116100fd5780635e0e5b3e146101ff578063715018a61461022f578063781952a81461024457806379ba50971461025957806387f8bf561461026e5780638da5cb5b1461029057600080fd5b8063158ef93e1461013a578063412601371461016957806343e316871461018b578063570ca735146101af57806359c19cee146101ec575b600080fd5b34801561014657600080fd5b506000546101549060ff1681565b60405190151581526020015b60405180910390f35b34801561017557600080fd5b50610189610184366004611eb5565b6103e0565b005b34801561019757600080fd5b506101a160015481565b604051908152602001610160565b3480156101bb57600080fd5b506000546101d49061010090046001600160a01b031681565b6040516001600160a01b039091168152602001610160565b6101896101fa366004611f2e565b610624565b34801561020b57600080fd5b5061015461021a366004611fa5565b60046020526000908152604090205460ff1681565b34801561023b57600080fd5b50610189610734565b34801561025057600080fd5b506005546101a1565b34801561026557600080fd5b50610189610748565b34801561027a57600080fd5b50610283610790565b6040516101609190611fbe565b34801561029c57600080fd5b506101d461081e565b6101896102b3366004611fa5565b610853565b3480156102c457600080fd5b506101896102d3366004611eb5565b61091c565b3480156102e457600080fd5b506101896102f336600461200c565b610a1e565b34801561030457600080fd5b50610283610a8f565b34801561031957600080fd5b506101a1610328366004611fa5565b610a9c565b34801561033957600080fd5b506101d473deaddeaddeaddeaddeaddeaddeaddeaddeaddead81565b34801561036157600080fd5b50610189610370366004612035565b610abd565b34801561038157600080fd5b506101d4611267565b34801561039657600080fd5b506101d46001603160981b0181565b3480156103b157600080fd5b506101a1662386f26fc1000081565b3480156103cc57600080fd5b506101896103db36600461200c565b611290565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146104485760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c65720060448201526064015b60405180910390fd5b60005460ff161561049b5760405162461bcd60e51b815260206004820152601f60248201527f436f6e747261637420697320616c726561647920696e697469616c697a656400604482015260640161043f565b806000036104eb5760405162461bcd60e51b815260206004820152601a60248201527f566572696669657220636f756e742063616e6e6f742062652030000000000000604482015260640161043f565b600084900361053c5760405162461bcd60e51b815260206004820152601e60248201527f4465706f736974207363726970742063616e6e6f7420626520656d7074790000604482015260640161043f565b6000805460ff191660011790556002610556858783612110565b506003610564838583612110565b50600181905560008054610100600160a81b03191674deaddeaddeaddeaddeaddeaddeaddeaddeaddead001781556040805191825273deaddeaddeaddeaddeaddeaddeaddeaddeaddead60208301527ffbe5b6cbafb274f445d7fed869dc77a838d8243a22c460de156560e8857cad03910160405180910390a17f89ed79f38bee253aee2fb8d52df0d71b4aaf0843800d093a499a55eeca455c3485858585856040516106159594939291906121f9565b60405180910390a15050505050565b61063581662386f26fc10000612249565b341461067d5760405162461bcd60e51b8152602060048201526017602482015276125b9d985b1a59081dda5d1a191c985dc8185b5bdd5b9d604a1b604482015260640161043f565b60055460005b8281101561072e57600584848381811061069f5761069f612260565b835460018101855560009485526020948590209190940292909201359190920155507fc96d1af655ee5eb07357bb1097f3b2f247ea0c4e3cf5f9a5c8449c4f8b64fb6b8484838181106106f4576106f4612260565b9050602002013582846107079190612276565b604080519283526020830191909152429082015260600160405180910390a1600101610683565b50505050565b61073c611315565b6107466000611347565b565b3380610752611267565b6001600160a01b0316146107845760405163118cdaa760e01b81526001600160a01b038216600482015260240161043f565b61078d81611347565b50565b6003805461079d90612087565b80601f01602080910402602001604051908101604052809291908181526020018280546107c990612087565b80156108165780601f106107eb57610100808354040283529160200191610816565b820191906000526020600020905b8154815290600101906020018083116107f957829003601f168201915b505050505081565b6000807f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c1993005b546001600160a01b031692915050565b662386f26fc1000034146108a35760405162461bcd60e51b8152602060048201526017602482015276125b9d985b1a59081dda5d1a191c985dc8185b5bdd5b9d604a1b604482015260640161043f565b600580546001810182556000919091527f036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db081018290556040805183815260208101839052428183015290517fc96d1af655ee5eb07357bb1097f3b2f247ea0c4e3cf5f9a5c8449c4f8b64fb6b9181900360600190a15050565b610924611315565b806000036109745760405162461bcd60e51b815260206004820152601a60248201527f566572696669657220636f756e742063616e6e6f742062652030000000000000604482015260640161043f565b60008490036109c55760405162461bcd60e51b815260206004820152601e60248201527f4465706f736974207363726970742063616e6e6f7420626520656d7074790000604482015260640161043f565b60026109d2858783612110565b5060036109e0838583612110565b5060018190556040517f89ed79f38bee253aee2fb8d52df0d71b4aaf0843800d093a499a55eeca455c349061061590879087908790879087906121f9565b610a26611315565b60008054610100600160a81b0319166101006001600160a01b038481168281029390931793849055604080519290940416815260208101919091527ffbe5b6cbafb274f445d7fed869dc77a838d8243a22c460de156560e8857cad03910160405180910390a150565b6002805461079d90612087565b60058181548110610aac57600080fd5b600091825260209091200154905081565b60005461010090046001600160a01b03163314610b1c5760405162461bcd60e51b815260206004820152601a60248201527f63616c6c6572206973206e6f7420746865206f70657261746f72000000000000604482015260640161043f565b6000610b7a610b2e6020840184612289565b610b3e60408501602086016122b3565b610b4b60408601866122dd565b610b5860608801886122dd565b610b6560808a018a6122dd565b610b7560c08c0160a08d01612289565b611383565b60008181526004602052604090205490915060ff1615610bd25760405162461bcd60e51b81526020600482015260136024820152721ddd1e125908185b1c9958591e481cdc195b9d606a1b604482015260640161043f565b60008181526004602052604090819020805460ff19166001179055610c3790610bfd908401846122dd565b8080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152506113cb92505050565b610c835760405162461bcd60e51b815260206004820152601d60248201527f56696e206973206e6f742070726f7065726c7920666f726d6174746564000000604482015260640161043f565b610ccd610c9360608401846122dd565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525061146f92505050565b610d195760405162461bcd60e51b815260206004820152601e60248201527f566f7574206973206e6f742070726f7065726c7920666f726d61747465640000604482015260640161043f565b6000610d65610d2b60408501856122dd565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525061150692505050565b91505080600114610db15760405162461bcd60e51b815260206004820152601660248201527513db9b1e481bdb99481a5b9c1d5d08185b1b1bddd95960521b604482015260640161043f565b610dfd610dc160808501856122dd565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525085925061151d915050565b610e535760405162461bcd60e51b815260206004820152602160248201527f5769746e657373206973206e6f742070726f7065726c7920666f726d617474656044820152601960fa1b606482015260840161043f565b6001603160981b01634ffd344a60e085013584610e7360c08801886122dd565b8861010001356040518663ffffffff1660e01b8152600401610e99959493929190612324565b602060405180830381865afa158015610eb6573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610eda9190612356565b610f265760405162461bcd60e51b815260206004820152601b60248201527f5472616e73616374696f6e206973206e6f7420696e20626c6f636b0000000000604482015260640161043f565b6000610f72610f3860808601866122dd565b8080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201829052509250611593915050565b90506000610f7f82611506565b9150506001546002610f919190612276565b8114610fd75760405162461bcd60e51b8152602060048201526015602482015274496e76616c6964207769746e657373206974656d7360581b604482015260640161043f565b6000610fe583600154611676565b9050600060028054610ff690612087565b915060009050611007838284611840565b905061109d816002805461101a90612087565b80601f016020809104026020016040519081016040528092919081815260200182805461104690612087565b80156110935780601f1061106857610100808354040283529160200191611093565b820191906000526020600020905b81548152906001019060200180831161107657829003601f168201915b5050505050611904565b6110e25760405162461bcd60e51b8152602060048201526016602482015275125b9d985b1a590819195c1bdcda5d081cd8dc9a5c1d60521b604482015260640161043f565b60006111116110f2846014612276565b6110fd856014612276565b86516111099190612378565b869190611840565b9050611124816003805461101a90612087565b6111685760405162461bcd60e51b8152602060048201526015602482015274092dcecc2d8d2c840e6c6e4d2e0e840e6eaccccd2f605b1b604482015260640161043f565b6000611173856119db565b604080518b81526001600160a01b0383166020820152428183015290519192507f182fa52899142d44ff5c45a6354d3b3e868d5b07db6a65580b39bd321bdaf8ac919081900360600190a16000816001600160a01b0316662386f26fc1000060405160006040518083038185875af1925050503d8060008114611212576040519150601f19603f3d011682016040523d82523d6000602084013e611217565b606091505b505090508061125a5760405162461bcd60e51b815260206004820152600f60248201526e151c985b9cd9995c8819985a5b1959608a1b604482015260640161043f565b5050505050505050505050565b6000807f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c00610843565b611298611315565b7f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c0080546001600160a01b0319166001600160a01b03831690811782556112dc61081e565b6001600160a01b03167f38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e2270060405160405180910390a35050565b3361131e61081e565b6001600160a01b0316146107465760405163118cdaa760e01b815233600482015260240161043f565b7f237e158222e3e6968b72b9db0d8043aacf074ad9f650f0d1606b4d82ee432c0080546001600160a01b031916815561137f82611a11565b5050565b60006113bd8a8a8a8a8a8a8a8a8a6040516020016113a99998979695949392919061238b565b604051602081830303815290604052611a82565b9a9950505050505050505050565b60008060006113d984611506565b90925090508015806113ec575060001982145b156113fb575060009392505050565b6000611408836001612276565b905060005b8281101561146257855182106114295750600095945050505050565b60006114358784611aa9565b9050600019810361144d575060009695505050505050565b6114578184612276565b92505060010161140d565b5093519093149392505050565b600080600061147d84611506565b9092509050801580611490575060001982145b1561149f575060009392505050565b60006114ac836001612276565b905060005b8281101561146257855182106114cd5750600095945050505050565b60006114d98784611af2565b905060001981036114f1575060009695505050505050565b6114fb8184612276565b9250506001016114b1565b600080611514836000611b56565b91509150915091565b60008160000361152f5750600061158d565b6000805b83811015611586578451821061154e5760009250505061158d565b600061155a8684611cfa565b90506000198103611571576000935050505061158d565b61157b8184612276565b925050600101611533565b5083511490505b92915050565b606060008060005b8481101561160c576115ad8683611cfa565b925060001983036115f85760405162461bcd60e51b815260206004820152601560248201527442616420566172496e7420696e207769746e65737360581b604482015260640161043f565b6116028383612276565b915060010161159b565b506116178582611cfa565b915060001982036116625760405162461bcd60e51b815260206004820152601560248201527442616420566172496e7420696e207769746e65737360581b604482015260640161043f565b61166d858284611840565b95945050505050565b606060008061168485611506565b9092509050600182016116e45760405162461bcd60e51b815260206004820152602260248201527f52656164206f76657272756e20647572696e6720566172496e742070617273696044820152616e6760f01b606482015260840161043f565b8084106117265760405162461bcd60e51b815260206004820152601060248201526f2b34b7103932b0b21037bb32b9393ab760811b604482015260640161043f565b600080611734846001612276565b905060005b868110156117bf5761174b8883611b56565b9095509250600183016117955760405162461bcd60e51b815260206004820152601260248201527142616420566172496e7420696e206974656d60701b604482015260640161043f565b826117a1866001612276565b6117ab9190612276565b6117b59083612276565b9150600101611739565b506117ca8782611b56565b9094509150600182016118145760405162461bcd60e51b815260206004820152601260248201527142616420566172496e7420696e206974656d60701b604482015260640161043f565b611835816118228685612276565b61182d906001612276565b899190611840565b979650505050505050565b60608160000361185f57506040805160208101909152600081526118fd565b600061186b8385612276565b9050838111801561187d575080855110155b6118bf5760405162461bcd60e51b8152602060048201526013602482015272536c696365206f7574206f6620626f756e647360681b604482015260640161043f565b604051915082604083010160405282825283850182038460208701018481015b808210156118f8578151838301526020820191506118df565b505050505b9392505050565b8151815160009190811461191c57600091505061158d565b60206000805b838311611952575050848101518482015160209092019180821461194d57600094505050505061158d565b611922565b600061195f602085612378565b90505b848110156119cd5786818151811061197c5761197c612260565b602001015160f81c60f81b6001600160f81b0319168882815181106119a3576119a3612260565b01602001516001600160f81b031916146119c55760009550505050505061158d565b600101611962565b506001979650505050505050565b600080600280546119eb90612087565b9150600090506119fd84836014611840565b611a06906123f4565b60601c949350505050565b7f9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c19930080546001600160a01b031981166001600160a01b03848116918217845560405192169182907f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e090600090a3505050565b60006020600083516020850160025afa50602060006020600060025afa5050600051919050565b6000806000611ab88585611d9c565b909250905060018201611ad1576000199250505061158d565b80611add836025612276565b611ae79190612276565b61166d906004612276565b6000611aff826009612276565b83511015611b10575060001961158d565b600080611b2785611b22866008612276565b611b56565b909250905060018201611b40576000199250505061158d565b80611b4c836009612276565b61166d9190612276565b6000806000611b658585611dde565b90508060ff16600003611b9a576000858581518110611b8657611b86612260565b016020015190935060f81c9150611cf39050565b83611ba6826001612447565b60ff16611bb39190612276565b85511015611bca5760001960009250925050611cf3565b60008160ff16600203611c0e57611c03611bef611be8876001612276565b8890611e64565b62ffff0060e882901c1660f89190911c1790565b61ffff169050611ce9565b8160ff16600403611c5d57611c50611c2a611be8876001612276565b60d881901c63ff00ff001662ff00ff60e89290921c9190911617601081811b91901c1790565b63ffffffff169050611ce9565b8160ff16600803611ce957611cdc611c79611be8876001612276565b60c01c64ff000000ff600882811c91821665ff000000ff009390911b92831617601090811b67ffffffffffffffff1666ff00ff00ff00ff9290921667ff00ff00ff00ff009093169290921790911c65ffff0000ffff1617602081811c91901b1790565b67ffffffffffffffff1690505b60ff909116925090505b9250929050565b6000806000611d098585611b56565b909250905060018201611d22576000199250505061158d565b600080611d30846001612276565b905060005b83811015611d9157611d4b88611b22848a612276565b909550925060018301611d67576000199550505050505061158d565b82611d73866001612276565b611d7d9190612276565b611d879083612276565b9150600101611d35565b509695505050505050565b600080611daa836025612276565b84511015611dbf575060001990506000611cf3565b600080611dd186611b22876024612276565b9097909650945050505050565b6000828281518110611df257611df2612260565b016020015160f81c60ff03611e095750600861158d565b828281518110611e1b57611e1b612260565b016020015160f81c60fe03611e325750600461158d565b828281518110611e4457611e44612260565b016020015160f81c60fd03611e5b5750600261158d565b50600092915050565b60006118fd8383016020015190565b60008083601f840112611e8557600080fd5b50813567ffffffffffffffff811115611e9d57600080fd5b602083019150836020828501011115611cf357600080fd5b600080600080600060608688031215611ecd57600080fd5b853567ffffffffffffffff811115611ee457600080fd5b611ef088828901611e73565b909650945050602086013567ffffffffffffffff811115611f1057600080fd5b611f1c88828901611e73565b96999598509660400135949350505050565b60008060208385031215611f4157600080fd5b823567ffffffffffffffff811115611f5857600080fd5b8301601f81018513611f6957600080fd5b803567ffffffffffffffff811115611f8057600080fd5b8560208260051b8401011115611f9557600080fd5b6020919091019590945092505050565b600060208284031215611fb757600080fd5b5035919050565b602081526000825180602084015260005b81811015611fec5760208186018101516040868401015201611fcf565b506000604082850101526040601f19601f83011684010191505092915050565b60006020828403121561201e57600080fd5b81356001600160a01b03811681146118fd57600080fd5b60006020828403121561204757600080fd5b813567ffffffffffffffff81111561205e57600080fd5b820161012081850312156118fd57600080fd5b634e487b7160e01b600052604160045260246000fd5b600181811c9082168061209b57607f821691505b6020821081036120bb57634e487b7160e01b600052602260045260246000fd5b50919050565b601f82111561210b57806000526020600020601f840160051c810160208510156120e85750805b601f840160051c820191505b8181101561210857600081556001016120f4565b50505b505050565b67ffffffffffffffff83111561212857612128612071565b61213c836121368354612087565b836120c1565b6000601f84116001811461217057600085156121585750838201355b600019600387901b1c1916600186901b178355612108565b600083815260209020601f19861690835b828110156121a15786850135825560209485019460019092019101612181565b50868210156121be5760001960f88860031b161c19848701351681555b505060018560011b0183555050505050565b81835281816020850137506000828201602090810191909152601f909101601f19169091010190565b60608152600061220d6060830187896121d0565b82810360208401526122208186886121d0565b9150508260408301529695505050505050565b634e487b7160e01b600052601160045260246000fd5b808202811582820484141761158d5761158d612233565b634e487b7160e01b600052603260045260246000fd5b8082018082111561158d5761158d612233565b60006020828403121561229b57600080fd5b81356001600160e01b0319811681146118fd57600080fd5b6000602082840312156122c557600080fd5b81356001600160f01b0319811681146118fd57600080fd5b6000808335601e198436030181126122f457600080fd5b83018035915067ffffffffffffffff82111561230f57600080fd5b602001915036819003821315611cf357600080fd5b8581528460208201526080604082015260006123446080830185876121d0565b90508260608301529695505050505050565b60006020828403121561236857600080fd5b815180151581146118fd57600080fd5b8181038181111561158d5761158d612233565b6001600160e01b03198a1681526001600160f01b031989166004820152868860068301376000878201600681016000815287898237506000908701600601908152848682376001600160e01b031993909316929093019182525060040198975050505050505050565b805160208201516bffffffffffffffffffffffff19811691906014821015612440576bffffffffffffffffffffffff196bffffffffffffffffffffffff198360140360031b1b82161692505b5050919050565b60ff818116838216019081111561158d5761158d61223356")),
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
