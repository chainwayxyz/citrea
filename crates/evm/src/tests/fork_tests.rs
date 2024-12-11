use std::collections::BTreeMap;
use std::str::FromStr;

use alloy_eips::BlockId;
use citrea_primitives::MIN_BASE_FEE_PER_GAS;
use reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT;
use reth_primitives::{
    address, b256, Address, BlockNumberOrTag, Bytes, Log, LogData, TxKind, B256, U64,
};
use reth_rpc_types::request::{TransactionInput, TransactionRequest};
use reth_rpc_types::BlockOverrides;
use revm::primitives::SpecId::SHANGHAI;
use revm::primitives::{hex, KECCAK_EMPTY, U256};
use revm::Database;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{
    Context, Module, SoftConfirmationModuleCallError, StateMapAccessor, StateVecAccessor,
};
use sov_rollup_interface::spec::SpecId as SovSpecId;

use crate::call::CallMessage;
use crate::evm::primitive_types::Receipt;
use crate::evm::DbAccount;
use crate::handler::{BROTLI_COMPRESSION_PERCENTAGE, L1_FEE_OVERHEAD};
use crate::smart_contracts::{
    BlockHashContract, InfiniteLoopContract, LogsContract, SelfDestructorContract,
    SimpleStorageContract, TestContract, TransientStorageContract,
};
use crate::tests::test_signer::TestSigner;
use crate::tests::utils::{
    config_push_contracts, create_contract_message, create_contract_message_with_fee,
    create_contract_message_with_fee_and_gas_limit, create_contract_transaction, get_evm,
    get_evm_config, get_evm_config_starting_base_fee, publish_event_message, set_arg_message,
};
use crate::tests::DEFAULT_CHAIN_ID;
use crate::{
    AccountData, EvmConfig, RlpEvmTransaction, BASE_FEE_VAULT, L1_FEE_VAULT, PRIORITY_FEE_VAULT,
};
type C = DefaultContext;

use super::call_tests::send_money_to_contract_message;

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

    // Last tx should have failed
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
    assert_eq!(receipts.last().unwrap().receipt.success, true);

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
    assert_eq!(receipts.last().unwrap().receipt.success, false);

    // TODO: Also add a function to transient storage contract to test mcopy or do a different contract for that
    // TODO: Use self destruct conttract to test the restriction of SELFDESTRUCT usage to the creating contract
}
