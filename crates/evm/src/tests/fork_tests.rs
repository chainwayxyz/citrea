use std::str::FromStr;
use std::thread::sleep;

use alloy_primitives::{address, keccak256, Address, Bytes, TxKind};
use revm::primitives::U256;
use sha2::Digest;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::fork::Fork;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, StateMapAccessor, StateVecAccessor};
use sov_rollup_interface::spec::SpecId as SovSpecId;

use crate::call::CallMessage;
use crate::evm::DbAccount;
use crate::smart_contracts::{
    BlobBaseFeeContract, KZGPointEvaluationCallerContract, McopyContract, SelfDestructorContract,
    SelfdestructingConstructorContract, SimpleStorageContract, TransientStorageContract,
};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{
    create_contract_message, get_evm, get_evm_config, get_evm_with_spec, set_arg_message,
};
use crate::RlpEvmTransaction;
type C = DefaultContext;

use super::call_tests::send_money_to_contract_message;
use super::utils::create_contract_message_with_bytecode;

const VERSIONED_HASH_VERSION_KZG: u8 = 1;

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

fn call_kzg_point_evaluation_transaction(
    contract_addr: Address,
    dev_signer: &TestSigner,
    nonce: u64,
    input: Bytes,
) -> RlpEvmTransaction {
    let contract = KZGPointEvaluationCallerContract::default();
    dev_signer
        .sign_default_transaction(
            TxKind::Call(contract_addr),
            contract.call_kzg_point_evaluation(input),
            nonce,
            0,
        )
        .unwrap()
}

#[test]
fn test_cancun_transient_storage_activation() {
    let (config, dev_signer, contract_addr) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set) = get_evm_with_spec(&config, SovSpecId::Genesis);
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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    l2_height += 1;

    let receipts: Vec<_> = evm
        .receipts_rlp
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
        current_spec: SovSpecId::Kumquat,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Kumquat, l1_fee_rate);
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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    l2_height += 1;

    let receipts: Vec<_> = evm
        .receipts_rlp
        .iter(&mut working_set.accessory_state())
        .collect();

    // Last tx should have passed
    assert!(receipts.last().unwrap().receipt.success);

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Kumquat, l1_fee_rate);
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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    let receipts: Vec<_> = evm
        .receipts_rlp
        .iter(&mut working_set.accessory_state())
        .collect();

    // This tx should fail as the contract has already been claimed
    assert!(!receipts.last().unwrap().receipt.success);
}

#[test]
fn test_cancun_mcopy_activation() {
    let (config, dev_signer, contract_addr) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let (mut evm, mut working_set) = get_evm_with_spec(&config, SovSpecId::Genesis);
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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    l2_height += 1;

    let receipts: Vec<_> = evm
        .receipts_rlp
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
        current_spec: SovSpecId::Kumquat,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    // Send money to transient storage contract
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Kumquat, l1_fee_rate);
        let call_tx = call_mcopy(contract_addr, &dev_signer, 2);

        evm.call(
            CallMessage { txs: vec![call_tx] },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    let receipts: Vec<_> = evm
        .receipts_rlp
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
        current_spec: SovSpecId::Kumquat,
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
        let context = C::new(sender_address, l2_height, SovSpecId::Kumquat, l1_fee_rate);

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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

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

    let (mut evm, mut working_set) = get_evm_with_spec(&config, SovSpecId::Genesis);
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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    l2_height += 1;

    for _ in 0..10 {
        evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
        evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
        evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());
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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());
    l2_height += 1;

    let receipts: Vec<_> = evm
        .receipts_rlp
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
        current_spec: SovSpecId::Kumquat,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Kumquat, l1_fee_rate);
        let call_tx = store_blob_base_fee_transaction(contract_addr, &dev_signer, 2);

        evm.call(
            CallMessage { txs: vec![call_tx] },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    let receipts: Vec<_> = evm
        .receipts_rlp
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

#[test]
fn test_kzg_point_eval_should_revert() {
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
        current_spec: SovSpecId::Kumquat,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    let sender_address = generate_address::<C>("sender");
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Kumquat, l1_fee_rate);

        let deploy_message =
            create_contract_message(&dev_signer, 0, KZGPointEvaluationCallerContract::default());

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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    l2_height += 1;

    // Implementation taken from https://eips.ethereum.org/EIPS/eip-4844#point-evaluation-precompile
    fn kzg_to_versioned_hash(commitment: Bytes) -> Bytes {
        let mut commitment_hash = sha2::Sha256::digest(commitment).to_vec();
        commitment_hash[0] = VERSIONED_HASH_VERSION_KZG;
        Bytes::from(commitment_hash)
    }

    // data is taken from: https://github.com/ethereum/c-kzg-4844/tree/main/tests/verify_kzg_proof/kzg-mainnet/verify_kzg_proof_case_correct_proof_d0992bc0387790a4
    let commitment= Bytes::from_str("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7").unwrap();
    let versioned_hash = kzg_to_versioned_hash(commitment.clone());
    let z = Bytes::from_str("5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62")
        .unwrap();
    let y = Bytes::from_str("4882cf0609af8c7cd4c256e63a35838c95a9ebbf6122540ab344b42fd66d32e1")
        .unwrap();
    let proof =  Bytes::from_str("0x987ea6df69bbe97c23e0dd948cf2d4490824ba7fea5af812721b2393354b0810a9dba2c231ea7ae30f26c412c7ea6e3a").unwrap();

    // The data is encoded as follows: versioned_hash | z | y | commitment | proof | with z and y being padded 32 byte big endian values
    // ref: https://eips.ethereum.org/EIPS/eip-4844#point-evaluation-precompile
    let mut input = vec![];
    input.extend_from_slice(&versioned_hash);
    input.extend_from_slice(&z);
    input.extend_from_slice(&y);
    input.extend_from_slice(&commitment);
    input.extend_from_slice(&proof);

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Kumquat, l1_fee_rate);

        let deploy_message = call_kzg_point_evaluation_transaction(
            contract_addr,
            &dev_signer,
            1,
            Bytes::from(input),
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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // expect this call to fail because we do not have the kzg feature of revm enabled on fork1
    let receipts: Vec<_> = evm
        .receipts_rlp
        .iter(&mut working_set.accessory_state())
        .collect();

    let db_account = DbAccount::new(contract_addr);
    let storage_value = db_account
        .storage
        .get(&U256::ZERO, &mut working_set)
        .unwrap();
    assert_ne!(
        storage_value,
        // expected if point eval precompile was enabled
        U256::from_str(
            "52435875175126190479447740508185965837690552500527637822603658699938581184513"
        )
        .unwrap()
    );
    assert!(receipts.last().unwrap().receipt.success);
}

#[test]
fn test_offchain_contract_storage_evm() {
    let (config, dev_signer, contract_addr) =
        get_evm_config(U256::from_str("100000000000000000000").unwrap(), None);

    let fork_fn = |num: u64| {
        if num < 3 {
            Fork::new(SovSpecId::Genesis, 0)
        } else {
            Fork::new(SovSpecId::Kumquat, 4)
        }
    };

    let (mut evm, mut working_set) = get_evm_with_spec(&config, SovSpecId::Genesis);
    let l1_fee_rate = 0;
    let mut l2_height = 2;

    // Deployed a contract in genesis fork
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

    let sender_address = generate_address::<C>("sender");
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Genesis, l1_fee_rate);

        let deploy_message =
            create_contract_message(&dev_signer, 0, SimpleStorageContract::default());

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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    l2_height += 1;

    sleep(std::time::Duration::from_secs(2));

    //try to get it from offchain storage and expect it to not exist
    let contract_info = evm.accounts.get(&contract_addr, &mut working_set);
    let code_hash = contract_info.unwrap().code_hash.unwrap();

    let genesis_cont_evm_code = evm.code.get(&code_hash, &mut working_set).unwrap();

    // Try to get the code from genesis fork and expect it to exist
    let code = evm
        .get_code_inner(contract_addr, None, &mut working_set, fork_fn)
        .unwrap();

    assert_eq!(*genesis_cont_evm_code.original_byte_slice(), code);

    let offchain_code = evm
        .offchain_code
        .get(&code_hash, &mut working_set.offchain_state());

    assert!(offchain_code.is_none());

    // activate fork and then try to get it from offchain storage and expect it to exist
    // Deployed a contract in genesis fork
    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Kumquat,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());
    sleep(std::time::Duration::from_secs(2));
    l2_height += 1;

    let offchain_code = evm
        .offchain_code
        .get(&code_hash, &mut working_set.offchain_state());

    assert!(offchain_code.is_none());

    let evm_code = evm.code.get(&code_hash, &mut working_set).unwrap();

    let code = evm
        .get_code_inner(
            contract_addr,
            Some(alloy_eips::BlockId::Number(
                alloy_eips::BlockNumberOrTag::Latest,
            )),
            &mut working_set,
            fork_fn,
        )
        .unwrap();

    assert_eq!(code, *evm_code.original_byte_slice());

    // Deploy contract in fork1
    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Kumquat, l1_fee_rate);

        let deploy_message =
            create_contract_message(&dev_signer, 1, SelfDestructorContract::default());

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
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());
    l2_height += 1;

    let new_contract_address = address!("d26ff5586e488e65d86bcc3f0fe31551e381a596");

    let contract_info = evm.accounts.get(&new_contract_address, &mut working_set);
    let code_hash = contract_info.unwrap().code_hash.unwrap();

    let offchain_code = evm
        .offchain_code
        .get(&code_hash, &mut working_set.offchain_state());

    assert!(offchain_code.is_some());

    let evm_code = evm.code.get(&code_hash, &mut working_set);
    assert!(evm_code.is_none());

    // make tx on the contract that was deployed before fork1 and see that you can read it from offchain storage afterwards
    let soft_confirmation_info = HookSoftConfirmationInfo {
        l2_height,
        da_slot_hash: [5u8; 32],
        da_slot_height: 1,
        da_slot_txs_commitment: [42u8; 32],
        pre_state_root: [10u8; 32].to_vec(),
        current_spec: SovSpecId::Kumquat,
        pub_key: vec![],
        deposit_data: vec![],
        l1_fee_rate,
        timestamp: 0,
    };

    evm.begin_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    {
        let context = C::new(sender_address, l2_height, SovSpecId::Kumquat, l1_fee_rate);

        let call_message = set_arg_message(contract_addr, &dev_signer, 2, 99);

        evm.call(
            CallMessage {
                txs: vec![call_message],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&soft_confirmation_info, &mut working_set);
    evm.finalize_hook(&[99u8; 32], &mut working_set.accessory_state());

    // Try to get the code from genesis fork and expect it to not exist because it is stored in offchain storage
    let code = evm
        .get_code_inner(new_contract_address, None, &mut working_set, fork_fn)
        .unwrap();
    assert_eq!(code, *offchain_code.unwrap().original_byte_slice());

    // Also try to get code of a contract deployed in genesis fork and expect it to exist as well
    let code = evm
        .get_code_inner(contract_addr, None, &mut working_set, fork_fn)
        .unwrap();
    assert_eq!(code, *genesis_cont_evm_code.original_byte_slice());

    // Now I should be able to read the contract from offchain storage
    let contract_info = evm.accounts.get(&contract_addr, &mut working_set);
    let code_hash = contract_info.unwrap().code_hash.unwrap();

    let offchain_code = evm
        .offchain_code
        .get(&code_hash, &mut working_set.offchain_state());

    assert!(offchain_code.is_some());
}
