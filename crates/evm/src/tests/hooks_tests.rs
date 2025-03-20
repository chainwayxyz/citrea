use alloy_primitives::hex_literal::hex;
use alloy_primitives::{Address, Bloom, Bytes, B256, B64, U256};
use lazy_static::lazy_static;
use rand::Rng;
use reth_primitives::{
    Header, Signature, TransactionSigned, TransactionSignedNoHash, EMPTY_OMMER_ROOT_HASH,
    KECCAK_EMPTY,
};
use revm::primitives::{BlobExcessGasAndPrice, BlockEnv};
use sov_modules_api::hooks::HookL2BlockInfo;
use sov_modules_api::{StateMapAccessor, StateValueAccessor, StateVecAccessor};
use sov_rollup_interface::spec::SpecId;

use crate::evm::primitive_types::{Block, Receipt, SealedBlock, TransactionSignedAndRecovered};
use crate::tests::genesis_tests::BENEFICIARY;
use crate::tests::utils::{get_evm, get_evm_test_config, GENESIS_STATE_ROOT};
use crate::tests::{get_test_seq_pub_key, DEFAULT_CHAIN_ID};
use crate::PendingTransaction;

lazy_static! {
    pub(crate) static ref DA_ROOT_HASH: B256 = B256::from([5u8; 32]);
}

#[test]
fn begin_l2_block_hook_creates_pending_block() {
    let config = get_evm_test_config();
    let (mut evm, mut working_set, _spec_id) = get_evm(&config);
    let l1_fee_rate = 0;
    let l2_height = 2;
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SpecId::Fork2,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 54,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);
    let pending_block = evm.block_env;
    assert_eq!(
        pending_block,
        BlockEnv {
            number: U256::from(2),
            coinbase: *BENEFICIARY,
            timestamp: U256::from(54),
            prevrandao: Some(B256::ZERO),
            basefee: U256::from(765625000),
            gas_limit: U256::from(config.block_gas_limit),
            difficulty: U256::ZERO,
            blob_excess_gas_and_price: Some(BlobExcessGasAndPrice::new(0))
        }
    );
}

#[test]
fn end_l2_block_hook_sets_head() {
    let config = get_evm_test_config();
    let (mut evm, mut working_set, _spec_id) = get_evm(&get_evm_test_config());

    let mut pre_state_root = [0u8; 32];
    pre_state_root.copy_from_slice(GENESIS_STATE_ROOT.as_ref());
    let l1_fee_rate = 0;
    let l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root,
        current_spec: SpecId::Fork2,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 54,
    };

    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    evm.pending_transactions
        .push(create_pending_transaction(1, 0));

    evm.pending_transactions
        .push(create_pending_transaction(2, 1));

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);
    let head = evm.head.get(&mut working_set).unwrap();
    let pending_head = evm
        .pending_head
        .get(&mut working_set.accessory_state())
        .unwrap();

    assert_eq!(head, pending_head);
    assert_eq!(
        head,
        Block {
            header: alloy_consensus::Header {
                parent_hash: B256::from(hex!(
                    "2bc99e5a9b733d0cfc105a23d3fff3a103d24757b3c395903782b79074eae75c"
                )),

                ommers_hash: EMPTY_OMMER_ROOT_HASH,
                beneficiary: config.coinbase,
                state_root: KECCAK_EMPTY,
                transactions_root: B256::from(hex!(
                    "090f386f4e0ba442a7fc48eb5e5b9b1b06e84e2877628d72d2ae7b135d08e4b9"
                )),
                receipts_root: B256::from(hex!(
                    "27036187b3f5e87d4306b396cf06c806da2cc9a0fef9b07c042e3b4304e01c64"
                )),
                withdrawals_root: None,
                logs_bloom: Bloom::new(hex!("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
                difficulty: U256::ZERO,
                number: 2,
                gas_limit: config.block_gas_limit,
                gas_used: 200u64,
                timestamp: 54,
                mix_hash: B256::ZERO,
                nonce: 0u64.into(),
                base_fee_per_gas: Some(765625000),
                extra_data: Bytes::default(),
                blob_gas_used: Some(0),
                excess_blob_gas: Some(0),
                parent_beacon_block_root: None,
                requests_root: None,
            },
            l1_fee_rate: 0,
            transactions: 0..2
        }
    );
}

#[test]
fn end_l2_block_hook_moves_transactions_and_receipts() {
    let (mut evm, mut working_set, _spec_id) = get_evm(&get_evm_test_config());
    let l1_fee_rate = 0;
    let l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: [10u8; 32],
        current_spec: SpecId::Fork2,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    let tx1 = create_pending_transaction(1, 0);
    evm.pending_transactions.push(tx1.clone());

    let tx2 = create_pending_transaction(2, 1);
    evm.pending_transactions.push(tx2.clone());

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);

    let tx1_hash = tx1.transaction.signed_transaction.hash;
    let tx2_hash = tx2.transaction.signed_transaction.hash;

    assert_eq!(
        evm.receipts
            .get(0, &mut working_set.accessory_state())
            .unwrap(),
        tx1.receipt
    );
    assert_eq!(
        evm.receipts
            .get(1, &mut working_set.accessory_state())
            .unwrap(),
        tx2.receipt
    );
    assert_eq!(
        evm.transactions
            .get(0, &mut working_set.accessory_state())
            .unwrap(),
        tx1.transaction
    );
    assert_eq!(
        evm.transactions
            .get(1, &mut working_set.accessory_state())
            .unwrap(),
        tx2.transaction
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

    assert_eq!(evm.pending_transactions.len(), 0);
}

fn create_pending_transaction(index: u64, nonce: u64) -> PendingTransaction {
    let tx = TransactionSignedNoHash {
        signature: Signature::new(U256::ZERO, U256::ZERO, false.into()),
        transaction: reth_primitives::Transaction::Eip1559(alloy_consensus::TxEip1559 {
            chain_id: DEFAULT_CHAIN_ID,
            nonce,
            gas_limit: 1000u64,
            max_fee_per_gas: 2000u64 as u128,
            max_priority_fee_per_gas: 3000u64 as u128,
            to: alloy_primitives::TxKind::Call(Address::from([3u8; 20])),
            value: U256::from(4000u128),
            access_list: alloy_rpc_types::AccessList::default(),
            input: Bytes::from([4u8; 20]),
        }),
    };

    PendingTransaction {
        transaction: TransactionSignedAndRecovered {
            signer: Address::from([1u8; 20]),
            signed_transaction: TransactionSigned {
                hash: tx.hash(),
                signature: tx.signature,
                transaction: tx.transaction,
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
    let config = get_evm_test_config();
    let (mut evm, mut working_set, _spec_id) = get_evm(&config);

    // hack to get the root hash
    let binding = evm
        .blocks
        .get(1, &mut working_set.accessory_state())
        .unwrap();
    let root = binding.header.header().state_root.0;

    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: root,
        current_spec: SpecId::Fork2,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 54,
    };
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    evm.pending_transactions
        .push(create_pending_transaction(1, 0));
    evm.pending_transactions
        .push(create_pending_transaction(2, 1));
    evm.end_l2_block_hook(&l2_block_info, &mut working_set);

    let root_hash = [99u8; 32];

    let mut accessory_state = working_set.accessory_state();
    evm.finalize_hook(&root_hash, &mut accessory_state);
    assert_eq!(evm.blocks.len(&mut accessory_state), 3);

    l2_height += 1;

    evm.begin_l2_block_hook(
        &HookL2BlockInfo {
            l2_height,
            pre_state_root: root_hash,
            current_spec: SpecId::Fork2,
            sequencer_pub_key: get_test_seq_pub_key(),
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
        beneficiary: config.coinbase,
        state_root: B256::from(root_hash),
        transactions_root: B256::from(hex!(
            "090f386f4e0ba442a7fc48eb5e5b9b1b06e84e2877628d72d2ae7b135d08e4b9"
        )),
        receipts_root: B256::from(hex!(
            "27036187b3f5e87d4306b396cf06c806da2cc9a0fef9b07c042e3b4304e01c64"
        )),
        withdrawals_root: None,
        logs_bloom: Bloom::new(hex!("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")),
        difficulty: U256::ZERO,
        number: 2,
        gas_limit: 30000000,
        gas_used: 200,
        timestamp: 54,
        mix_hash: B256::ZERO,
        nonce: B64::ZERO,
        base_fee_per_gas: Some(765625000),
        extra_data: Bytes::default(),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: None,
        requests_root: None,
    };

    let hash = header.hash_slow();
    // let sealed = header.seal_slow();
    // let (header, seal) = sealed.into_parts();
    assert_eq!(
        block,
        SealedBlock {
            header: reth_primitives::SealedHeader::new(header, hash),
            l1_fee_rate: 0,
            transactions: 0..2
        }
    );

    assert_eq!(
        evm.block_hashes
            .get(&block.header.hash(), &mut accessory_state)
            .unwrap(),
        2u64
    );

    assert_eq!(evm.pending_head.get(&mut accessory_state), None);
}

#[test]
// this test is run with Fork2 spec
// because pre fork2 we were deleting block hashes and
// we'd still like to test that
fn begin_l2_block_hook_appends_last_block_hashes() {
    let (mut evm, mut working_set, _spec_id) = get_evm(&get_evm_test_config());

    // hack to get the root hash
    let binding = evm
        .blocks
        .get(1, &mut working_set.accessory_state())
        .unwrap();
    let root = binding.header.header().state_root.0;

    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: root,
        current_spec: SpecId::Fork2,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    // on block 2, only block 0 and 1 exists
    for i in 0..2 {
        assert_eq!(
            evm.latest_block_hashes.get(&i, &mut working_set).unwrap(),
            evm.blocks
                .get(i as usize, &mut working_set.accessory_state())
                .unwrap()
                .header
                .hash()
        );
    }

    assert!(evm.latest_block_hashes.get(&2, &mut working_set).is_none());

    evm.end_l2_block_hook(&l2_block_info, &mut working_set);

    let mut random_32_bytes: [u8; 32] = rand::thread_rng().gen::<[u8; 32]>();
    evm.finalize_hook(&random_32_bytes, &mut working_set.accessory_state());

    l2_height += 1;

    // finalize blocks 2-257 with random state root hashes
    for _ in 2..257 {
        let l1_fee_rate = 0;
        let l2_block_info = HookL2BlockInfo {
            l2_height,
            pre_state_root: random_32_bytes,
            current_spec: SpecId::Fork2,
            sequencer_pub_key: get_test_seq_pub_key(),
            l1_fee_rate,
            timestamp: 0,
        };
        evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

        evm.end_l2_block_hook(&l2_block_info, &mut working_set);

        random_32_bytes = rand::thread_rng().gen::<[u8; 32]>();
        evm.finalize_hook(&random_32_bytes, &mut working_set.accessory_state());

        l2_height += 1;
    }

    // start environment for block 258
    let l1_fee_rate = 0;
    let l2_block_info = HookL2BlockInfo {
        l2_height,
        pre_state_root: random_32_bytes,
        current_spec: SpecId::Fork2,
        sequencer_pub_key: get_test_seq_pub_key(),
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_l2_block_hook(&l2_block_info, &mut working_set);

    assert_eq!(
        evm.latest_block_hashes.get(&257, &mut working_set).unwrap(),
        evm.blocks
            .get(257, &mut working_set.accessory_state())
            .unwrap()
            .header
            .hash()
    );
}
