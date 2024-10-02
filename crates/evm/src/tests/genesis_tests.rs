use std::collections::HashMap;

use alloy_eips::eip1559::BaseFeeParams;
use lazy_static::lazy_static;
use reth_primitives::constants::{EMPTY_RECEIPTS, EMPTY_TRANSACTIONS, ETHEREUM_BLOCK_GAS_LIMIT};
use reth_primitives::hex_literal::hex;
use reth_primitives::{
    Address, Bloom, Bytes, Header, SealedHeader, B256, EMPTY_OMMER_ROOT_HASH, KECCAK_EMPTY, U256,
};
use revm::primitives::SpecId;
use sov_modules_api::prelude::*;

use crate::evm::primitive_types::SealedBlock;
use crate::evm::{AccountInfo, EvmChainConfig};
use crate::tests::utils::{get_evm, GENESIS_HASH, GENESIS_STATE_ROOT};
use crate::{AccountData, EvmConfig};

lazy_static! {
    pub(crate) static ref TEST_CONFIG: EvmConfig = EvmConfig {
        data: vec![AccountData {
            address: Address::from([1u8; 20]),
            balance: U256::checked_mul(U256::from(1000), U256::pow(U256::from(10), U256::from(18))).unwrap(), // 1000 ETH
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: Default::default(),
        },
        AccountData {
            address:Address::from([2u8; 20]),
            balance: U256::checked_mul(U256::from(1000),
            U256::pow(U256::from(10), U256::from(18))).unwrap(), // 1000 ETH,
            code_hash: hex!("4e8ee9adb469b245e3a5a8e58e9b733aaa857a9dce1982257531db8a2700aabf").into(),
            code: hex!("60606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a223e05d1461006a578063").into(),
            storage: {
                let mut storage = HashMap::new();
                storage.insert(U256::from(0), U256::from(0x4321));
                storage.insert(
                    U256::from_be_slice(
                        &hex!("6661e9d6d8b923d5bbaab1b96e1dd51ff6ea2a93520fdc9eb75d059238b8c5e9")[..],
                    ),
                    U256::from(8),
                );

                storage
            },
            nonce: 1
        }],
        spec: vec![(0, SpecId::BERLIN), (1, SpecId::SHANGHAI)]
            .into_iter()
            .collect(),
        chain_id: 1000,
        block_gas_limit: reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT,
        coinbase: Address::from([3u8; 20]),
        limit_contract_code_size: Some(5000),
        starting_base_fee: 1000000000,
        base_fee_params: BaseFeeParams::ethereum(),
        timestamp: 0,
        difficulty: U256::ZERO,
        extra_data: Bytes::default(),
        nonce: 0,
    };

    pub(crate) static ref GENESIS_DA_TXS_COMMITMENT: B256 = B256::from(hex!(
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    ));
    pub(crate) static ref BENEFICIARY: Address = Address::from([3u8; 20]);
}

#[test]
fn genesis_data() {
    let (evm, mut working_set) = get_evm(&TEST_CONFIG);

    let account = &TEST_CONFIG.data[0];

    let db_account = evm.accounts.get(&account.address, &working_set).unwrap();

    let contract = &TEST_CONFIG.data[1];

    let contract_account = evm.accounts.get(&contract.address, &working_set).unwrap();

    let contract_storage1 = evm
        .get_storage_at(contract.address, U256::from(0), None, &mut working_set)
        .unwrap();

    let contract_storage2 = evm
        .get_storage_at(
            contract.address,
            U256::from_be_slice(
                &hex::decode("6661e9d6d8b923d5bbaab1b96e1dd51ff6ea2a93520fdc9eb75d059238b8c5e9")
                    .unwrap(),
            ),
            None,
            &mut working_set,
        )
        .unwrap();

    assert_eq!(
        db_account,
        AccountInfo {
            balance: account.balance,
            code_hash: None,
            nonce: account.nonce,
        }
    );

    assert_eq!(
        contract_account,
        AccountInfo {
            balance: contract.balance,
            code_hash: Some(contract.code_hash),
            nonce: contract.nonce,
        }
    );

    assert_eq!(
        contract_storage1,
        B256::from_slice(
            hex::decode("0000000000000000000000000000000000000000000000000000000000004321")
                .unwrap()
                .as_slice()
        )
    );
    assert_eq!(
        contract_storage2,
        B256::from_slice(
            hex::decode("0000000000000000000000000000000000000000000000000000000000000008")
                .unwrap()
                .as_slice()
        )
    );
}

#[test]
fn genesis_cfg() {
    let (evm, mut working_set) = get_evm(&TEST_CONFIG);

    let cfg = evm.cfg.get(&mut working_set).unwrap();
    assert_eq!(
        cfg,
        EvmChainConfig {
            spec: vec![(0, SpecId::BERLIN), (1, SpecId::SHANGHAI)],
            chain_id: 1000,
            block_gas_limit: reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT,
            coinbase: Address::from([3u8; 20]),
            limit_contract_code_size: Some(5000),
            base_fee_params: BaseFeeParams::ethereum(),
        }
    );
}

#[test]
#[should_panic(expected = "EVM spec must start from block 0")]
fn genesis_cfg_missing_specs() {
    get_evm(&EvmConfig {
        spec: vec![(5, SpecId::BERLIN)].into_iter().collect(),
        ..Default::default()
    });
}

#[test]
fn genesis_empty_spec_defaults_to_shanghai() {
    let mut config = TEST_CONFIG.clone();
    config.spec.clear();
    let (evm, mut working_set) = get_evm(&config);

    let cfg = evm.cfg.get(&mut working_set).unwrap();
    assert_eq!(cfg.spec, vec![(0, SpecId::SHANGHAI)]);
}

#[test]
#[should_panic(expected = "Cancun is not supported")]
fn genesis_cfg_cancun() {
    get_evm(&EvmConfig {
        spec: vec![(0, SpecId::CANCUN)].into_iter().collect(),
        ..Default::default()
    });
}

#[test]
fn genesis_block() {
    let (evm, mut working_set) = get_evm(&TEST_CONFIG);

    let mut accessory_state = working_set.accessory_state();

    let block_number = evm
        .block_hashes
        .get(&GENESIS_HASH, &accessory_state)
        .unwrap();

    let block = evm
        .blocks
        .get(block_number as usize, &mut accessory_state)
        .unwrap();

    assert_eq!(block_number, 0);

    assert_eq!(
        block,
        SealedBlock {
            header: SealedHeader::new(
                Header {
                    parent_hash: B256::default(),
                    state_root: *GENESIS_STATE_ROOT,
                    transactions_root: EMPTY_TRANSACTIONS,
                    receipts_root: EMPTY_RECEIPTS,
                    logs_bloom: Bloom::default(),
                    difficulty: U256::ZERO,
                    number: 0,
                    gas_limit: ETHEREUM_BLOCK_GAS_LIMIT,
                    gas_used: 0,
                    timestamp: 0,
                    extra_data: Bytes::default(),
                    mix_hash: B256::default(),
                    nonce: 0,
                    base_fee_per_gas: Some(1000000000),
                    ommers_hash: EMPTY_OMMER_ROOT_HASH,
                    beneficiary: *BENEFICIARY,
                    withdrawals_root: None,
                    blob_gas_used: None,
                    excess_blob_gas: None,
                    parent_beacon_block_root: None,
                    requests_root: None,
                },
                *GENESIS_HASH
            ),
            l1_fee_rate: 0,
            l1_hash: [0; 32].into(),
            transactions: (0u64..0u64),
        }
    );
}

#[test]
fn genesis_head() {
    let (evm, mut working_set) = get_evm(&TEST_CONFIG);
    let head = evm.head.get(&mut working_set).unwrap();

    assert_eq!(head.header.parent_hash, *GENESIS_HASH);
    let genesis_block = evm
        .blocks
        .get(0, &mut working_set.accessory_state())
        .unwrap();

    assert_eq!(
        *genesis_block.header.header(),
        Header {
            parent_hash: B256::default(),
            state_root: *GENESIS_STATE_ROOT,
            transactions_root: EMPTY_TRANSACTIONS,
            receipts_root: EMPTY_RECEIPTS,
            logs_bloom: Bloom::default(),
            difficulty: U256::ZERO,
            number: 0,
            gas_limit: ETHEREUM_BLOCK_GAS_LIMIT,
            gas_used: 0,
            timestamp: 0,
            extra_data: Bytes::default(),
            mix_hash: B256::default(),
            nonce: 0,
            base_fee_per_gas: Some(1000000000),
            ommers_hash: EMPTY_OMMER_ROOT_HASH,
            beneficiary: *BENEFICIARY,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_root: None,
        }
    );

    assert_eq!(genesis_block.l1_fee_rate, 0);

    assert_eq!(genesis_block.transactions, (0u64..0u64));
}
