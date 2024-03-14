use lazy_static::lazy_static;
use rand::Rng;
use reth_primitives::hex_literal::hex;
use reth_primitives::{
    Address, Bloom, Bytes, Header, SealedHeader, Signature, TransactionSigned, B256,
    EMPTY_OMMER_ROOT_HASH, KECCAK_EMPTY, U256,
};
use sov_modules_api::{StateMapAccessor, StateValueAccessor, StateVecAccessor};

use super::genesis_tests::{get_evm, TEST_CONFIG};
use crate::evm::primitive_types::{
    Block, BlockEnv, Receipt, SealedBlock, TransactionSignedAndRecovered,
};
use crate::tests::genesis_tests::{BENEFICIARY, GENESIS_HASH, GENESIS_STATE_ROOT};
use crate::tests::DEFAULT_CHAIN_ID;
use crate::PendingTransaction;

lazy_static! {
    pub(crate) static ref DA_ROOT_HASH: B256 = B256::from([5u8; 32]);
}

#[test]
fn begin_soft_confirmation_hook_creates_pending_block() {
    let (evm, mut working_set) = get_evm(&TEST_CONFIG);
    let l1_fee_rate = 0;
    evm.begin_soft_confirmation_hook(DA_ROOT_HASH.0, &[10u8; 32], l1_fee_rate, &mut working_set);
    let pending_block = evm.block_env.get(&mut working_set).unwrap();
    assert_eq!(
        pending_block,
        BlockEnv {
            number: 1,
            coinbase: *BENEFICIARY,
            timestamp: TEST_CONFIG.genesis_timestamp + TEST_CONFIG.block_timestamp_delta,
            prevrandao: *DA_ROOT_HASH,
            basefee: 875000000,
            gas_limit: TEST_CONFIG.block_gas_limit,
        }
    );
}

#[test]
fn end_soft_confirmation_hook_sets_head() {
    let (evm, mut working_set) = get_evm(&TEST_CONFIG);
    let mut pre_state_root = [0u8; 32];
    pre_state_root.copy_from_slice(GENESIS_STATE_ROOT.as_ref());
    let l1_fee_rate = 0;

    evm.begin_soft_confirmation_hook(
        DA_ROOT_HASH.0,
        GENESIS_STATE_ROOT.as_ref(),
        l1_fee_rate,
        &mut working_set,
    );

    evm.pending_transactions.push(
        &create_pending_transaction(B256::from([1u8; 32]), 1),
        &mut working_set,
    );

    evm.pending_transactions.push(
        &create_pending_transaction(B256::from([2u8; 32]), 2),
        &mut working_set,
    );

    evm.end_soft_confirmation_hook(&mut working_set);
    let head = evm.head.get(&mut working_set).unwrap();
    let pending_head = evm
        .pending_head
        .get(&mut working_set.accessory_state())
        .unwrap();

    assert_eq!(head, pending_head);
    assert_eq!(
        head,
        Block {
            header: Header {
                // TODO: temp parent hash until: https://github.com/Sovereign-Labs/sovereign-sdk/issues/876
                parent_hash: *GENESIS_HASH,

                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                beneficiary: TEST_CONFIG.coinbase,
                state_root: KECCAK_EMPTY,
                transactions_root: B256::from(hex!(
                    "30eb5f6050df7ea18ca34cf3503f4713119315a2d3c11f892c5c8920acf816f4"
                )),
                receipts_root: B256::from(hex!(
                    "27036187b3f5e87d4306b396cf06c806da2cc9a0fef9b07c042e3b4304e01c64"
                )),
                withdrawals_root: None,
                logs_bloom: Bloom::default(),
                difficulty: U256::ZERO,
                number: 1,
                gas_limit: TEST_CONFIG.block_gas_limit,
                gas_used: 200u64,
                timestamp: TEST_CONFIG.genesis_timestamp + TEST_CONFIG.block_timestamp_delta,
                mix_hash: *DA_ROOT_HASH,
                nonce: 0,
                base_fee_per_gas: Some(875000000),
                extra_data: Bytes::default(),
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
            },
            transactions: 0..2
        }
    );
}

#[test]
fn end_soft_confirmation_hook_moves_transactions_and_receipts() {
    let (evm, mut working_set) = get_evm(&TEST_CONFIG);
    let l1_fee_rate = 0;
    evm.begin_soft_confirmation_hook(DA_ROOT_HASH.0, &[10u8; 32], l1_fee_rate, &mut working_set);

    let tx1 = create_pending_transaction(B256::from([1u8; 32]), 1);
    evm.pending_transactions.push(&tx1, &mut working_set);

    let tx2 = create_pending_transaction(B256::from([2u8; 32]), 2);
    evm.pending_transactions.push(&tx2, &mut working_set);

    evm.end_soft_confirmation_hook(&mut working_set);

    let tx1_hash = tx1.transaction.signed_transaction.hash;
    let tx2_hash = tx2.transaction.signed_transaction.hash;

    assert_eq!(
        evm.transactions
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [tx1.transaction, tx2.transaction]
    );

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [tx1.receipt, tx2.receipt]
    );

    assert_eq!(
        evm.transaction_hashes
            .get(&tx1_hash, &mut working_set.accessory_state())
            .unwrap(),
        0
    );

    assert_eq!(
        evm.transaction_hashes
            .get(&tx2_hash, &mut working_set.accessory_state())
            .unwrap(),
        1
    );

    assert_eq!(evm.pending_transactions.len(&mut working_set), 0);
}

fn create_pending_transaction(hash: B256, index: u64) -> PendingTransaction {
    PendingTransaction {
        transaction: TransactionSignedAndRecovered {
            signer: Address::from([1u8; 20]),
            signed_transaction: TransactionSigned {
                hash,
                signature: Signature::default(),
                transaction: reth_primitives::Transaction::Eip1559(reth_primitives::TxEip1559 {
                    chain_id: DEFAULT_CHAIN_ID,
                    nonce: 1u64,
                    gas_limit: 1000u64,
                    max_fee_per_gas: 2000u64 as u128,
                    max_priority_fee_per_gas: 3000u64 as u128,
                    to: reth_primitives::TransactionKind::Call(Address::from([3u8; 20])),
                    value: U256::from(4000u128),
                    access_list: reth_primitives::AccessList::default(),
                    input: Bytes::from([4u8; 20]),
                }),
            },
            block_number: 1,
        },
        receipt: Receipt {
            receipt: reth_primitives::Receipt {
                tx_type: reth_primitives::TxType::Eip1559,
                success: true,
                cumulative_gas_used: 100u64 * index,
                logs: vec![],
            },
            gas_used: 100u64,
            log_index_start: 0,
            l1_fee_rate: 0,
            diff_size: 0,
            error: None,
        },
    }
}

#[test]
fn finalize_hook_creates_final_block() {
    let (evm, mut working_set) = get_evm(&TEST_CONFIG);
    let mut pre_state_root = [0u8; 32];
    pre_state_root.copy_from_slice(GENESIS_STATE_ROOT.as_ref());
    let l1_fee_rate = 0;

    evm.begin_soft_confirmation_hook(
        DA_ROOT_HASH.0,
        GENESIS_STATE_ROOT.as_ref(),
        l1_fee_rate,
        &mut working_set,
    );
    evm.pending_transactions.push(
        &create_pending_transaction(B256::from([1u8; 32]), 1),
        &mut working_set,
    );
    evm.pending_transactions.push(
        &create_pending_transaction(B256::from([2u8; 32]), 2),
        &mut working_set,
    );
    evm.end_soft_confirmation_hook(&mut working_set);

    let root_hash = [99u8; 32];

    let mut accessory_state = working_set.accessory_state();
    evm.finalize_hook(&root_hash.into(), &mut accessory_state);
    assert_eq!(evm.blocks.len(&mut accessory_state), 2);
    let l1_fee_rate = 0;

    evm.begin_soft_confirmation_hook(DA_ROOT_HASH.0, &root_hash, l1_fee_rate, &mut working_set);

    let mut accessory_state = working_set.accessory_state();

    let parent_block = evm.blocks.get(0usize, &mut accessory_state).unwrap();
    let parent_hash = parent_block.header.hash();
    let block = evm.blocks.get(1usize, &mut accessory_state).unwrap();

    assert_eq!(
        block,
        SealedBlock {
            header: SealedHeader::new(
                Header {
                    parent_hash,
                    ommers_hash: EMPTY_OMMER_ROOT_HASH,
                    beneficiary: TEST_CONFIG.coinbase,
                    state_root: B256::from(root_hash),
                    transactions_root: B256::from(hex!(
                        "30eb5f6050df7ea18ca34cf3503f4713119315a2d3c11f892c5c8920acf816f4"
                    )),
                    receipts_root: B256::from(hex!(
                        "27036187b3f5e87d4306b396cf06c806da2cc9a0fef9b07c042e3b4304e01c64"
                    )),
                    withdrawals_root: None,
                    logs_bloom: Bloom::default(),
                    difficulty: U256::ZERO,
                    number: 1,
                    gas_limit: 30000000,
                    gas_used: 200,
                    timestamp: 52,
                    mix_hash: B256::from(hex!(
                        "0505050505050505050505050505050505050505050505050505050505050505"
                    )),
                    nonce: 0,
                    base_fee_per_gas: Some(875000000),
                    extra_data: Bytes::default(),
                    blob_gas_used: None,
                    excess_blob_gas: None,
                    parent_beacon_block_root: None,
                },
                B256::from(hex!(
                    "4850cef91960c3097715d9294018ea79399b71d80db8b8e6089788059ddc903d"
                ))
            ),
            transactions: 0..2
        }
    );

    assert_eq!(
        evm.block_hashes
            .get(&block.header.hash(), &mut accessory_state)
            .unwrap(),
        1u64
    );

    assert_eq!(evm.pending_head.get(&mut accessory_state), None);
}

#[test]
fn begin_soft_confirmation_hook_appends_last_block_hashes() {
    let (evm, mut working_set) = get_evm(&TEST_CONFIG);

    let mut state_root = [0u8; 32];
    state_root.copy_from_slice(&GENESIS_STATE_ROOT.0);
    let l1_fee_rate = 0;

    evm.begin_soft_confirmation_hook(DA_ROOT_HASH.0, &state_root, l1_fee_rate, &mut working_set);

    // on block 1, only block 0 exists, so the last block hash should be the genesis hash
    // the others should not exist
    assert_eq!(
        evm.latest_block_hashes
            .get(&U256::from(0), &mut working_set)
            .unwrap(),
        evm.blocks
            .get(0, &mut working_set.accessory_state())
            .unwrap()
            .header
            .hash()
    );

    assert!(evm
        .latest_block_hashes
        .get(&U256::from(1), &mut working_set)
        .is_none());

    evm.end_soft_confirmation_hook(&mut working_set);

    let mut random_32_bytes: [u8; 32] = rand::thread_rng().gen::<[u8; 32]>();
    evm.finalize_hook(&random_32_bytes.into(), &mut working_set.accessory_state());

    // finalize blocks 1-256 with random state root hashes
    for _ in 1..256 {
        let l1_fee_rate = 0;
        evm.begin_soft_confirmation_hook(
            DA_ROOT_HASH.0,
            &random_32_bytes,
            l1_fee_rate,
            &mut working_set,
        );

        evm.end_soft_confirmation_hook(&mut working_set);

        random_32_bytes = rand::thread_rng().gen::<[u8; 32]>();
        evm.finalize_hook(&random_32_bytes.into(), &mut working_set.accessory_state());
    }

    // start environment for block 257
    let l1_fee_rate = 0;
    evm.begin_soft_confirmation_hook(
        DA_ROOT_HASH.0,
        &random_32_bytes,
        l1_fee_rate,
        &mut working_set,
    );

    // only the last 256 blocks should exist on block 257
    // which is [1, 256]
    // not 0
    assert_eq!(
        evm.latest_block_hashes
            .get(&U256::from(256), &mut working_set)
            .unwrap(),
        evm.blocks
            .get(256, &mut working_set.accessory_state())
            .unwrap()
            .header
            .hash()
    );

    assert!(evm
        .latest_block_hashes
        .get(&U256::from(0), &mut working_set)
        .is_none());
    assert!(evm
        .latest_block_hashes
        .get(&U256::from(257), &mut working_set)
        .is_none());
    assert!(evm
        .latest_block_hashes
        .get(&U256::from(1), &mut working_set)
        .is_some());
}
