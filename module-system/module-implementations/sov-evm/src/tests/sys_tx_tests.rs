use std::str::FromStr;

use reth_primitives::{TransactionKind, TransactionSignedEcRecovered, TransactionSignedNoHash};
use revm::primitives::U256;
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, StateMapAccessor, StateVecAccessor};

use crate::call::CallMessage;
use crate::evm::primitive_types::Receipt;
use crate::signer::SYSTEM_SIGNER;
use crate::smart_contracts::{BlockHashContract, TestContract};
use crate::tests::call_tests::get_evm_config_starting_base_fee;
use crate::tests::genesis_tests::get_evm;
use crate::tests::test_signer::TestSigner;
use crate::RlpEvmTransaction;

type C = DefaultContext;

fn create_system_contract_message_with_fee<T: TestContract>(
    dev_signer: &TestSigner,
    nonce: u64,
    contract: T,
    max_fee_per_gas: u128,
) -> RlpEvmTransaction {
    dev_signer
        .sign_system_transaction_with_fee(
            TransactionKind::Create,
            contract.byte_code().to_vec(),
            nonce,
            0,
            max_fee_per_gas,
        )
        .unwrap()
}

#[test]
fn test_system_caller() {
    let (config, dev_signer, _) =
        get_evm_config_starting_base_fee(U256::from_str("1000000").unwrap(), None, 1);

    let (evm, mut working_set) = get_evm(&config);
    let l1_fee_rate = 1;

    let deploy_message =
        create_system_contract_message_with_fee(&dev_signer, 0, BlockHashContract::default(), 1);

    let signed_no_hash = TransactionSignedNoHash::try_from(deploy_message.clone()).unwrap();
    assert!(
        signed_no_hash.recover_signer().is_none(),
        "System signed message must be unrecoverable"
    );

    let signed_recovered: TransactionSignedEcRecovered =
        TransactionSignedEcRecovered::try_from(deploy_message.clone()).unwrap();
    assert_eq!(
        signed_recovered.signer(),
        SYSTEM_SIGNER,
        "SYSTEM_SIGNATURE must be transformed into SYSTEM_SIGNER"
    );

    let system_account = evm.accounts.get(&SYSTEM_SIGNER, &mut working_set);
    assert!(
        system_account.is_none(),
        "There is no system account before call"
    ); // That's optional but if the acc will exist in the future its balance must be zero.

    evm.begin_soft_confirmation_hook([5u8; 32], &[10u8; 32], l1_fee_rate, &mut working_set);
    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(sender_address, sequencer_address, 1);

        evm.call(
            CallMessage {
                txs: vec![deploy_message],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let system_account = evm.accounts.get(&SYSTEM_SIGNER, &mut working_set).unwrap();
    // The system caller balance is unchanged(if exists)/or should be 0
    assert_eq!(system_account.info.balance, U256::from(0));
    assert_eq!(system_account.info.nonce, 1);

    let coinbase_account = evm.accounts.get(&config.coinbase, &mut working_set);
    assert!(coinbase_account.is_none());

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [Receipt {
            receipt: reth_primitives::Receipt {
                tx_type: reth_primitives::TxType::Eip1559,
                success: true,
                cumulative_gas_used: 114235,
                logs: vec![],
            },
            gas_used: 114235,
            log_index_start: 0,
            diff_size: 477,
            error: None,
        },]
    )
}
