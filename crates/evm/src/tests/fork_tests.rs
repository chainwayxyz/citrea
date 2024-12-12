use std::str::FromStr;

use reth_primitives::{address, Address, TxKind};
use revm::primitives::U256;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, StateMapAccessor, StateVecAccessor};
use sov_rollup_interface::spec::SpecId as SovSpecId;

use crate::call::CallMessage;
use crate::evm::DbAccount;
use crate::smart_contracts::{
    BlobBaseFeeContract, McopyContract, SelfDestructorContract, SelfdestructingConstructorContract,
    TransientStorageContract,
};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{create_contract_message, get_evm, get_evm_config};
use crate::RlpEvmTransaction;
type C = DefaultContext;

use super::call_tests::{
    selfdestruct_message, send_money_to_contract_message, set_selfdestruct_arg_message,
};
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

        let result = evm
            .call(
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

        let result = evm
            .call(
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

        let result = evm
            .call(
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

    l2_height += 1;

    let receipts: Vec<_> = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect();

    let txs: Vec<_> = evm
        .transactions
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

// tests first part of https://eips.ethereum.org/EIPS/eip-6780
#[test]
fn test_self_destruct_restriction() {
    let contract_balance: u64 = 1000000000000000;

    // address used in selfdestruct
    let die_to_address = address!("11115497b157177315e1204f52e588b393111111");

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

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);

        // deploy selfdestruct contract
        // send some money to the selfdestruct contract
        // set some variable in the contract
        let rlp_transactions = vec![
            create_contract_message(&dev_signer, 0, SelfDestructorContract::default()),
            send_money_to_contract_message(contract_addr, &dev_signer, 1, contract_balance as u128),
            set_selfdestruct_arg_message(contract_addr, &dev_signer, 2, 123),
        ];

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

    l2_height += 1;

    let contract_info = evm
        .accounts
        .get(&contract_addr, &mut working_set)
        .expect("contract address should exist");

    // Test if we managed to send money to contract
    assert_eq!(contract_info.balance, U256::from(contract_balance));

    let db_contract = DbAccount::new(contract_addr);

    // Test if we managed to set the variable in the contract
    assert_eq!(
        db_contract
            .storage
            .get(&U256::from(0), &mut working_set)
            .unwrap(),
        U256::from(123)
    );

    // Test if the key is set in the keys statevec
    assert_eq!(db_contract.keys.len(&mut working_set), 1);
    let l1_fee_rate = 0;

    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 2,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [99u8; 32].to_vec(),
        current_spec: SovSpecId::Genesis,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);
        // selfdestruct
        evm.call(
            CallMessage {
                txs: vec![selfdestruct_message(
                    contract_addr,
                    &dev_signer,
                    3,
                    die_to_address,
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

    // we now delete destructed accounts from storage
    assert_eq!(evm.accounts.get(&contract_addr, &mut working_set), None);

    let die_to_acc = evm
        .accounts
        .get(&die_to_address, &mut working_set)
        .expect("die to address should exist");

    let receipts = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect::<Vec<_>>();

    // the tx should be a success
    assert!(receipts[0].receipt.success);

    // the to address balance should be equal to contract balance
    assert_eq!(die_to_acc.balance, U256::from(contract_balance));

    let db_account = DbAccount::new(contract_addr);

    // the storage should be empty
    assert_eq!(
        db_account.storage.get(&U256::from(0), &mut working_set),
        None
    );

    // the keys should be empty
    assert_eq!(db_account.keys.len(&mut working_set), 0);
    let new_contract_address = address!("e04dd177927f4293a16f9c3f990b45afebc0e12c");
    // Now deploy selfdestruct contract again
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);

        // deploy selfdestruct contract
        // send some money to the selfdestruct contract
        // set some variable in the contract
        let rlp_transactions = vec![
            create_contract_message(&dev_signer, 4, SelfDestructorContract::default()),
            send_money_to_contract_message(
                new_contract_address,
                &dev_signer,
                5,
                contract_balance as u128,
            ),
            set_selfdestruct_arg_message(new_contract_address, &dev_signer, 6, 123),
        ];

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

    l2_height += 1;

    let contract_info = evm
        .accounts
        .get(&new_contract_address, &mut working_set)
        .expect("contract address should exist");

    let new_contract_code_hash_before_destruct = contract_info.code_hash.unwrap();

    // Activate fork1
    // After cancun activated here SELFDESTRUCT will recover all funds to the target
    // but not delete the account, except when called in the same transaction as creation
    // In this case the contract does not have a selfdestruct in the same transaction as creation
    // https://eips.ethereum.org/EIPS/eip-6780
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
        let sender_address = generate_address::<C>("sender");
        let context = C::new(sender_address, l2_height, SovSpecId::Fork1, l1_fee_rate);
        // selfdestruct to die to address with someone other than the creator of the contract
        evm.call(
            CallMessage {
                txs: vec![selfdestruct_message(
                    new_contract_address,
                    &dev_signer,
                    7,
                    die_to_address,
                )],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let receipts = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect::<Vec<_>>();

    // the tx should be a success
    assert!(receipts[0].receipt.success);

    // after cancun the funds go but account is not destructed if if selfdestruct is not called in creation
    let contract_info = evm
        .accounts
        .get(&new_contract_address, &mut working_set)
        .expect("contract address should exist");

    // Test if we managed to send money to contract
    assert_eq!(contract_info.nonce, 0);
    assert_eq!(
        contract_info.code_hash.unwrap(),
        new_contract_code_hash_before_destruct
    );

    // Test if we managed to send money to contract
    assert_eq!(contract_info.balance, U256::from(0));

    let die_to_contract = evm
        .accounts
        .get(&die_to_address, &mut working_set)
        .expect("die to address should exist");

    // the to address balance should be equal to double contract balance now that two selfdestructs have been called
    assert_eq!(die_to_contract.balance, U256::from(2 * contract_balance));

    let db_account = DbAccount::new(new_contract_address);

    // the storage should not be empty
    assert_eq!(
        db_account.storage.get(&U256::from(0), &mut working_set),
        Some(U256::from(123))
    );
}

// tests second part (last one) of https://eips.ethereum.org/EIPS/eip-6780
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

    for i in 0..10 {
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
    assert_eq!(receipts.last().unwrap().receipt.success, false);

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
    l2_height += 1;

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
