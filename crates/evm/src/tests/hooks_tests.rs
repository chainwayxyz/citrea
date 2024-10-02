use lazy_static::lazy_static;
use rand::Rng;
use reth_primitives::hex_literal::hex;
use reth_primitives::{
    Address, Bloom, Bytes, Header, Signature, TransactionSigned, B256, EMPTY_OMMER_ROOT_HASH,
    KECCAK_EMPTY, U256,
};
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::{StateMapAccessor, StateValueAccessor, StateVecAccessor};
use sov_rollup_interface::spec::SpecId;

use super::genesis_tests::{GENESIS_DA_TXS_COMMITMENT, TEST_CONFIG};
use crate::evm::primitive_types::{
    Block, BlockEnv, Receipt, SealedBlock, TransactionSignedAndRecovered,
};
use crate::tests::genesis_tests::BENEFICIARY;
use crate::tests::utils::{get_evm, GENESIS_STATE_ROOT};
use crate::tests::DEFAULT_CHAIN_ID;
use crate::PendingTransaction;

lazy_static! {
    pub(crate) static ref DA_ROOT_HASH: B256 = B256::from([5u8; 32]);
}

#[test]
fn begin_soft_confirmation_hook_creates_pending_block() {
    let (mut evm, mut working_set) = get_evm(&TEST_CONFIG);
    let l1_fee_rate = 0;
    let l2_height = 2;
    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: DA_ROOT_HASH.0,
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 54,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    let pending_block = evm.block_env;
    assert_eq!(
        pending_block,
        BlockEnv {
            number: 2,
            coinbase: *BENEFICIARY,
            timestamp: 54,
            prevrandao: *DA_ROOT_HASH,
            basefee: 765625000,
            gas_limit: TEST_CONFIG.block_gas_limit,
        }
    );
}

#[test]
fn end_soft_confirmation_hook_sets_head() {
    let (mut evm, mut working_set) = get_evm(&TEST_CONFIG);

    let mut pre_state_root = [0u8; 32];
    pre_state_root.copy_from_slice(GENESIS_STATE_ROOT.as_ref());
    let txs_commitment = *GENESIS_DA_TXS_COMMITMENT;
    let l1_fee_rate = 0;
    let l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: DA_ROOT_HASH.0,
        da_slot_height: 1,
        da_slot_txs_commitment: txs_commitment.into(),
        pre_state_root: pre_state_root.to_vec(),
        current_spec: SpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 54,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    evm.pending_transactions
        .push(create_pending_transaction(B256::from([1u8; 32]), 1));

    evm.pending_transactions
        .push(create_pending_transaction(B256::from([2u8; 32]), 2));

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
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
                parent_hash: B256::from(hex!(
                    "3c83b326074b9430d4899991bbb06b8517315c50ca2cb17c11e1e972afce1b02"
                )),

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
                number: 2,
                gas_limit: TEST_CONFIG.block_gas_limit,
                gas_used: 200u64,
                timestamp: 54,
                mix_hash: *DA_ROOT_HASH,
                nonce: 0,
                base_fee_per_gas: Some(765625000),
                extra_data: Bytes::default(),
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
                requests_root: None,
            },
            l1_fee_rate: 0,
            l1_hash: B256::from(DA_ROOT_HASH.0),
            transactions: 0..2
        }
    );
}

#[test]
fn end_soft_confirmation_hook_moves_transactions_and_receipts() {
    let (mut evm, mut working_set) = get_evm(&TEST_CONFIG);
    let l1_fee_rate = 0;
    let l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: DA_ROOT_HASH.0,
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

    let tx1 = create_pending_transaction(B256::from([1u8; 32]), 1);
    evm.pending_transactions.push(tx1.clone());

    let tx2 = create_pending_transaction(B256::from([2u8; 32]), 2);
    evm.pending_transactions.push(tx2.clone());

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

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
            .get(&tx1_hash, &working_set.accessory_state())
            .unwrap(),
        0
    );

    assert_eq!(
        evm.transaction_hashes
            .get(&tx2_hash, &working_set.accessory_state())
            .unwrap(),
        1
    );

    assert_eq!(evm.pending_transactions.len(), 0);
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
                    to: reth_primitives::TxKind::Call(Address::from([3u8; 20])),
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
            gas_used: 100,
            log_index_start: 0,
            l1_diff_size: 0,
        },
    }
}

#[test]
fn finalize_hook_creates_final_block() {
    let (mut evm, mut working_set) = get_evm(&TEST_CONFIG);

    // hack to get the root hash
    let binding = evm
        .blocks
        .get(1, &mut working_set.accessory_state())
        .unwrap();
    let root = binding.header.header().state_root.as_slice();

    let txs_commitment = *GENESIS_DA_TXS_COMMITMENT;
    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: txs_commitment.into(),
        pre_state_root: root.to_vec(),
        current_spec: SpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 54,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    evm.pending_transactions
        .push(create_pending_transaction(B256::from([1u8; 32]), 1));
    evm.pending_transactions
        .push(create_pending_transaction(B256::from([2u8; 32]), 2));
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    let root_hash = [99u8; 32];

    let mut accessory_state = working_set.accessory_state();
    evm.finalize_hook(&root_hash.into(), &mut accessory_state);
    assert_eq!(evm.blocks.len(&mut accessory_state), 3);

    l2_height += 1;

    evm.begin_soft_confirmation_hook(
        &HookSoftConfirmationInfo {
            l2_height,
            da_slot_hash: DA_ROOT_HASH.0,
            da_slot_height: 1,
            da_slot_txs_commitment: txs_commitment.into(),
            pre_state_root: root_hash.to_vec(),
            current_spec: SpecId::Genesis,
            pub_key: vec![],
            deposit_data: vec![],
            l1_fee_rate,
            timestamp: 54,
        },
        &mut working_set,
    );

    let mut accessory_state = working_set.accessory_state();

    let parent_block = evm.blocks.get(1usize, &mut accessory_state).unwrap();
    let parent_hash = parent_block.header.hash();
    let block = evm.blocks.get(2usize, &mut accessory_state).unwrap();

    let header = Header {
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
        number: 2,
        gas_limit: 30000000,
        gas_used: 200,
        timestamp: 54,
        mix_hash: B256::from(hex!(
            "0505050505050505050505050505050505050505050505050505050505050505"
        )),
        nonce: 0,
        base_fee_per_gas: Some(765625000),
        extra_data: Bytes::default(),
        blob_gas_used: None,
        excess_blob_gas: None,
        parent_beacon_block_root: None,
        requests_root: None,
    };
    assert_eq!(
        block,
        SealedBlock {
            header: header.seal_slow(),
            l1_fee_rate: 0,
            l1_hash: B256::from(DA_ROOT_HASH.0),
            transactions: 0..2
        }
    );

    assert_eq!(
        evm.block_hashes
            .get(&block.header.hash(), &accessory_state)
            .unwrap(),
        2u64
    );

    assert_eq!(evm.pending_head.get(&mut accessory_state), None);
}

#[test]
fn begin_soft_confirmation_hook_appends_last_block_hashes() {
    let (mut evm, mut working_set) = get_evm(&TEST_CONFIG);

    // hack to get the root hash
    let binding = evm
        .blocks
        .get(1, &mut working_set.accessory_state())
        .unwrap();
    let root = binding.header.header().state_root.as_slice();

    let txs_commitment = *GENESIS_DA_TXS_COMMITMENT;
    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: DA_ROOT_HASH.0,
        da_slot_height: 1,
        da_slot_txs_commitment: txs_commitment.into(),
        pre_state_root: root.to_vec(),
        current_spec: SpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    // on block 2, only block 0 and 1 exists
    for i in 0..2 {
        assert_eq!(
            evm.latest_block_hashes
                .get(&U256::from(i), &working_set)
                .unwrap(),
            evm.blocks
                .get(i, &mut working_set.accessory_state())
                .unwrap()
                .header
                .hash()
        );
    }

    assert!(evm
        .latest_block_hashes
        .get(&U256::from(2), &working_set)
        .is_none());

    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    let mut random_32_bytes: [u8; 32] = rand::thread_rng().gen::<[u8; 32]>();
    evm.finalize_hook(&random_32_bytes.into(), &mut working_set.accessory_state());

    l2_height += 1;

    // finalize blocks 2-257 with random state root hashes
    for _ in 2..257 {
        let l1_fee_rate = 0;
        let soft_confirmation_info = HookSoftConfirmationInfo {
            l2_height,
            da_slot_hash: DA_ROOT_HASH.0,
            da_slot_height: 1,
            da_slot_txs_commitment: random_32_bytes,
            pre_state_root: random_32_bytes.to_vec(),
            current_spec: SpecId::Genesis,
            pub_key: vec![],
            deposit_data: vec![],
            l1_fee_rate,
            timestamp: 0,
        };
        evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

        evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

        random_32_bytes = rand::thread_rng().gen::<[u8; 32]>();
        evm.finalize_hook(&random_32_bytes.into(), &mut working_set.accessory_state());

        l2_height += 1;
    }

    // start environment for block 258
    let l1_fee_rate = 0;
    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: DA_ROOT_HASH.0,
        da_slot_height: 1,
        da_slot_txs_commitment: random_32_bytes,
        pre_state_root: random_32_bytes.to_vec(),
        current_spec: SpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);

    // only the last 256 blocks should exist on block 258
    // which is [2, 257]
    // not 0 and 1
    assert_eq!(
        evm.latest_block_hashes
            .get(&U256::from(256), &working_set)
            .unwrap(),
        evm.blocks
            .get(256, &mut working_set.accessory_state())
            .unwrap()
            .header
            .hash()
    );

    assert!(evm
        .latest_block_hashes
        .get(&U256::from(0), &working_set)
        .is_none());
    assert!(evm
        .latest_block_hashes
        .get(&U256::from(1), &working_set)
        .is_none());
    assert!(evm
        .latest_block_hashes
        .get(&U256::from(258), &working_set)
        .is_none());
    assert!(evm
        .latest_block_hashes
        .get(&U256::from(2), &working_set)
        .is_some());
}
