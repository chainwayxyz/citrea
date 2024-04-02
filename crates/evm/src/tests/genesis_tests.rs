use std::collections::HashMap;

use hex::FromHex;
use lazy_static::lazy_static;
use reth_primitives::constants::{EMPTY_RECEIPTS, EMPTY_TRANSACTIONS, ETHEREUM_BLOCK_GAS_LIMIT};
use reth_primitives::hex_literal::hex;
use reth_primitives::{
    Address, BaseFeeParams, Bloom, Bytes, Header, SealedHeader, B256, EMPTY_OMMER_ROOT_HASH,
};
use revm::primitives::{SpecId, KECCAK_EMPTY, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::prelude::*;
use sov_modules_api::{Module, WorkingSet};
use sov_prover_storage_manager::new_orphan_storage;

use super::queries::commit;
use crate::evm::primitive_types::SealedBlock;
use crate::evm::{AccountInfo, DbAccount, EvmChainConfig};
use crate::{AccountData, Evm, EvmConfig};

type C = DefaultContext;

lazy_static! {
    pub(crate) static ref TEST_CONFIG: EvmConfig = EvmConfig {
        data: vec![AccountData {
            address: Address::from([1u8; 20]),
            balance: U256::checked_mul(U256::from(1000), U256::pow(U256::from(10), U256::from(18))).unwrap(), // 1000 ETH
            code_hash: KECCAK_EMPTY,
            code: Bytes::default(),
            nonce: 0,
            storage: None,
        },
        AccountData {
            address:Address::from([2u8; 20]),
            balance: U256::checked_mul(U256::from(1000),
            U256::pow(U256::from(10), U256::from(18))).unwrap(), // 1000 ETH,
            code_hash: B256::from_slice(&[2u8; 32]), code: Bytes::from_hex("60606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a223e05d1461006a578063").unwrap(), storage: {
                let mut storage = HashMap::new();
                storage.insert(U256::from(0), U256::from(0x4321));
                storage.insert(
                    U256::from_be_slice(
                        &hex::decode("6661e9d6d8b923d5bbaab1b96e1dd51ff6ea2a93520fdc9eb75d059238b8c5e9").unwrap(),
                    ),
                    U256::from(8),
                );

                Some(storage)
            },
            nonce: 1
        }],
        spec: vec![(0, SpecId::BERLIN), (1, SpecId::SHANGHAI)]
            .into_iter()
            .collect(),
        chain_id: 1000,
        block_gas_limit: reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT,
        block_timestamp_delta: 2,
        genesis_timestamp: 50,
        coinbase: Address::from([3u8; 20]),
        limit_contract_code_size: Some(5000),
        starting_base_fee: 1000000000,
        base_fee_params: BaseFeeParams::ethereum(),
    };

    pub(crate) static ref GENESIS_HASH: B256 = B256::from(hex!(
        "5c3afd4e90c378a3807947cfbaab0485031a4a2f647e1c5323777997338775a0"
    ));
    pub(crate) static ref GENESIS_STATE_ROOT: B256 = B256::from(hex!(
        "aad642e56d49fbdb0a7b7ad7da81490fde7cb22b3860c77ae92c4c1d37af98b4"
    ));
    pub(crate) static ref GENESIS_DA_TXS_COMMITMENT: B256 = B256::from(hex!(
        "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    ));
    pub(crate) static ref BENEFICIARY: Address = Address::from([3u8; 20]);
}

#[test]
fn genesis_data() {
    let (evm, mut working_set) = get_evm(&TEST_CONFIG);

    let account = &TEST_CONFIG.data[0];

    let db_account = evm
        .accounts
        .get(&account.address, &mut working_set)
        .unwrap();

    let contract = &TEST_CONFIG.data[1];

    let contract_account = evm
        .accounts
        .get(&contract.address, &mut working_set)
        .unwrap();

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

    let evm_db = evm.get_db(&mut working_set);

    assert_eq!(
        db_account,
        DbAccount::new_with_info(
            evm_db.accounts.prefix(),
            TEST_CONFIG.data[0].address,
            AccountInfo {
                balance: account.balance,
                code_hash: account.code_hash,
                nonce: account.nonce,
            }
        ),
    );

    assert_eq!(
        contract_account,
        DbAccount::new_with_info(
            evm_db.accounts.prefix(),
            contract.address,
            AccountInfo {
                balance: contract.balance,
                code_hash: contract.code_hash,
                nonce: contract.nonce,
            }
        ),
    );

    assert_eq!(contract_storage1, U256::from(0x4321));
    assert_eq!(contract_storage2, U256::from(8));
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
            block_timestamp_delta: 2,
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
        .get(&GENESIS_HASH, &mut accessory_state)
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
                    timestamp: 50,
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
                },
                *GENESIS_HASH
            ),
            l1_fee_rate: 0,
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
            timestamp: 50,
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
        }
    );

    assert_eq!(genesis_block.l1_fee_rate, 0);

    assert_eq!(genesis_block.transactions, (0u64..0u64));
}

pub(crate) fn get_evm(config: &EvmConfig) -> (Evm<C>, WorkingSet<DefaultContext>) {
    let tmpdir = tempfile::tempdir().unwrap();
    let storage = new_orphan_storage(tmpdir.path()).unwrap();
    let mut working_set = WorkingSet::new(storage.clone());
    let evm = Evm::<C>::default();
    evm.genesis(config, &mut working_set).unwrap();

    let root = commit(working_set, storage.clone());

    let mut working_set: WorkingSet<DefaultContext> = WorkingSet::new(storage.clone());
    evm.finalize_hook(&root.into(), &mut working_set.accessory_state());

    evm.begin_soft_confirmation_hook([1u8; 32], [2u8; 32], &root, 0, &mut working_set);
    evm.end_soft_confirmation_hook(&mut working_set);

    let root = commit(working_set, storage.clone());
    let mut working_set: WorkingSet<DefaultContext> = WorkingSet::new(storage.clone());
    evm.finalize_hook(&root.into(), &mut working_set.accessory_state());

    // let mut genesis_state_root = [0u8; 32];
    // genesis_state_root.copy_from_slice(GENESIS_STATE_ROOT.as_ref());

    (evm, working_set)
}
