use std::str::FromStr;

use reth_primitives::{address, keccak256, Address, TxKind};
use revm::primitives::U256;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, StateMapAccessor, StateVecAccessor};
use sov_rollup_interface::spec::SpecId as SovSpecId;

use crate::call::CallMessage;
use crate::evm::DbAccount;
use crate::smart_contracts::{
    BlobBaseFeeContract, McopyContract, SelfdestructingConstructorContract,
    TransientStorageContract,
};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{create_contract_message, get_evm, get_evm_config};
use crate::RlpEvmTransaction;
type C = DefaultContext;

use super::call_tests::send_money_to_contract_message;
use super::utils::create_contract_message_with_bytecode;

fn claim_gift_from_transient_storage_contract_transaction(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
) -> RlpEvmTransaction {
    let contract = TransientStorageContract::default();
    dev_signer
        .sign_default_transaction(TxKind::Call(contract_addr), contract.claim_gift(), nonce, 0)
        .unwrap()
}

fn call_mcopy(contract_addr: Address, dev_signer: &TestSigner, nonce: u64) -> RlpEvmTransaction {
    let contract = McopyContract::default();
    dev_signer
        .sign_default_transaction(TxKind::Call(contract_addr), contract.call_mcopy(), nonce, 0)
        .unwrap()
}

fn store_blob_base_fee_transaction(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
) -> RlpEvmTransaction {
    let contract = BlobBaseFeeContract::default();
    dev_signer
        .sign_default_transaction(
            TxKind::Call(contract_addr),
            contract.store_blob_base_fee(),
            nonce,
            0,
        )
        .unwrap()
}

#[test]
fn test_cancun_transient_storage_activation() {
    let (config, dev_signer, contract_addr) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set) = get_evm(&config);
    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    // Deploy transient storage contract
    let sender_address = generate_address::<C>("sender");
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);

        let deploy_message =
            create_contract_message(&dev_signer, 0, TransientStorageContract::default());

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

    l2_height += 1;

    // Send money to transient storage contract
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);
        let call_tx =
            send_money_to_contract_message(contract_addr, &dev_signer, 1, 10000000000000000000);

        evm.call(
            CallMessage { txs: vec![call_tx] },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    l2_height += 1;

    // Call claim gift from transient storage contract expect to fail on genesis spec
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);
        let call_tx =
            claim_gift_from_transient_storage_contract_transaction(contract_addr, &dev_signer, 2);

        evm.call(
            CallMessage { txs: vec![call_tx] },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    l2_height += 1;

    let receipts: Vec<_> = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect();

    // Last tx should have failed because cancun is not activated
    assert!(!receipts.last().unwrap().receipt.success);

    // Now trying with CANCUN spec on the next block
    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Fork1,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Fork1, l1_fee_rate);
        let call_tx =
            claim_gift_from_transient_storage_contract_transaction(contract_addr, &dev_signer, 3);

        evm.call(
            CallMessage { txs: vec![call_tx] },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    l2_height += 1;

    let receipts: Vec<_> = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect();

    // Last tx should have passed
    assert!(receipts.last().unwrap().receipt.success);

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Fork1, l1_fee_rate);
        let call_tx =
            claim_gift_from_transient_storage_contract_transaction(contract_addr, &dev_signer, 4);

        evm.call(
            CallMessage { txs: vec![call_tx] },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let receipts: Vec<_> = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect();

    // This tx should fail as the contract has already been claimed
    assert!(!receipts.last().unwrap().receipt.success);
}

#[test]
fn test_cancun_mcopy_activation() {
    let (config, dev_signer, contract_addr) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set) = get_evm(&config);
    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    // Deploy transient storage contract
    let sender_address = generate_address::<C>("sender");
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);

        let deploy_message = create_contract_message(&dev_signer, 0, McopyContract::default());

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

    l2_height += 1;

    // Send money to transient storage contract
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);
        let call_tx = call_mcopy(contract_addr, &dev_signer, 1);

        evm.call(
            CallMessage { txs: vec![call_tx] },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    l2_height += 1;

    let receipts: Vec<_> = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect();

    // Last tx should have failed because cancun is not activated
    assert!(!receipts.last().unwrap().receipt.success);

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Fork1,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    // Send money to transient storage contract
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Fork1, l1_fee_rate);
        let call_tx = call_mcopy(contract_addr, &dev_signer, 2);

        evm.call(
            CallMessage { txs: vec![call_tx] },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let receipts: Vec<_> = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect();

    // Last tx should have failed because cancun is not activated
    assert!(receipts.last().unwrap().receipt.success);
    let db_account = DbAccount::new(contract_addr);
    let storage_value = db_account
        .storage
        .get(&U256::ZERO, &mut working_set)
        .unwrap();
    assert_eq!(storage_value, U256::from(80));
}

// tests second part (last one) of https://eips.ethereum.org/EIPS/eip-6780
// First pat is in call_tests.rs `test_self_destruct_restriction`
#[test]
fn test_self_destructing_constructor() {
    let contract_balance: u128 = 1000000000000000;

    // address used in selfdestruct
    let die_to_address = address!("11115497b157177315e1204f52e588b393111111");

    let (config, dev_signer, contract_addr) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set) = get_evm(&config);
    let l1_fee_rate = 0;
    let l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Fork1,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };
    let contract = SelfdestructingConstructorContract::default();

    let constructed_bytecode = contract.construct(die_to_address);

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::Fork1, l1_fee_rate);

        // deploy selfdestruct contract
        let rlp_transactions = vec![create_contract_message_with_bytecode(
            &dev_signer,
            0,
            constructed_bytecode,
            Some(contract_balance),
        )];

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

    let contract_info = evm.accounts.get(&contract_addr, &mut working_set);
    // Contract should not exist as it is created and selfdestructed in the same transaction
    assert!(contract_info.is_none());

    let die_to_contract_info = evm.accounts.get(&die_to_address, &mut working_set);

    // die_to_address should have the contract balance
    assert!(die_to_contract_info.is_some());

    assert_eq!(
        die_to_contract_info.unwrap().balance,
        U256::from(contract_balance)
    );

    // after destruction codes should also be removed
    // calculated with
    // `solc --combined-json bin-runtime SelfdestructingConstructor.sol``
    let contract_runtime_bytecode_str = "60806040525f5ffdfea26469706673582212203744a38e5d136aea11a6095d6338eb5db0faba76bc0f7ee3aea38556128d0e9764736f6c634300081c0033";
    let contract_runtime_bytecode = hex::decode(contract_runtime_bytecode_str).unwrap();

    let contract_code_hash = keccak256(contract_runtime_bytecode.as_slice());

    let code = evm.code.get(&contract_code_hash, &mut working_set);
    assert!(code.is_none());

    let off_chain_code = evm
        .offchain_code
        .get(&contract_code_hash, &mut working_set.offchain_state());
    assert!(off_chain_code.is_none());
}

#[test]
fn test_blob_base_fee_should_return_1() {
    let (config, dev_signer, contract_addr) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set) = get_evm(&config);
    let l1_fee_rate = 0;
    let mut l2_height = 2;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    // Deploy transient storage contract
    let sender_address = generate_address::<C>("sender");
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);

        let deploy_message =
            create_contract_message(&dev_signer, 0, BlobBaseFeeContract::default());

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

    l2_height += 1;

    for _ in 0..10 {
        evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
        evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
        evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());
        l2_height += 1;
    }

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);
        let call_tx = store_blob_base_fee_transaction(contract_addr, &dev_signer, 1);

        evm.call(
            CallMessage { txs: vec![call_tx] },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());
    l2_height += 1;

    let receipts: Vec<_> = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect();

    // Last tx should have failed because cancun is not activated
    assert!(!receipts.last().unwrap().receipt.success);

    // Now trying with CANCUN spec on the next block
    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Fork1,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Fork1, l1_fee_rate);
        let call_tx = store_blob_base_fee_transaction(contract_addr, &dev_signer, 2);

        evm.call(
            CallMessage { txs: vec![call_tx] },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let receipts: Vec<_> = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect();

    // Last tx should have passed
    assert!(receipts.last().unwrap().receipt.success);

    let db_account = DbAccount::new(contract_addr);
    let storage_value = db_account
        .storage
        .get(&U256::ZERO, &mut working_set)
        .unwrap();

    assert_eq!(storage_value, U256::from(1));
}
