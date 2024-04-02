// use std::str::FromStr;

// use reth_primitives::{address, b256};
// use revm::primitives::{Bytes, U256};
// use sov_modules_api::default_context::DefaultContext;
// use sov_modules_api::utils::generate_address;
// use sov_modules_api::{Context, Module, StateMapAccessor, StateVecAccessor};

// use crate::call::CallMessage;
// use crate::evm::primitive_types::Receipt;
// use crate::smart_contracts::BlockHashContract;
// use crate::tests::call_tests::{
//     create_contract_message_with_fee, get_evm_config_starting_base_fee,
// };
// use crate::tests::genesis_tests::get_evm;
// use crate::{AccountData, SYSTEM_SIGNER};

// type C = DefaultContext;

// #[test]
// fn test_system_caller() {
//     let (mut config, dev_signer, _) =
//         get_evm_config_starting_base_fee(U256::from_str("1000000").unwrap(), None, 1);

//     config.data.push(AccountData {
//         address: address!("3100000000000000000000000000000000000001"),
//         balance: U256::ZERO,
//         code_hash: b256!("3e6de602146067c01322e2528a8f320c504fd3d19a4d6c4c53b54d2b2f9357ec"),
//         code: Bytes::from_static(b"0x60606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063a223e05d1461006a578063abd1a0cf1461008d578063abfced1d146100d4578063e05c914a14610110578063e6768b451461014c575b610000565b346100005761007761019d565b6040518082815260200191505060405180910390f35b34610000576100be600480803573ffffffffffffffffffffffffffffffffffffffff169060200190919050506101a3565b6040518082815260200191505060405180910390f35b346100005761010e600480803573ffffffffffffffffffffffffffffffffffffffff169060200190919080359060200190919050506101ed565b005b346100005761014a600480803590602001909190803573ffffffffffffffffffffffffffffffffffffffff16906020019091905050610236565b005b346100005761017960048080359060200190919080359060200190919080359060200190919050506103c4565b60405180848152602001838152602001828152602001935050505060405180910390f35b60005481565b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205490505b919050565b80600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055505b5050565b7f6031a8d62d7c95988fa262657cd92107d90ed96e08d8f867d32f26edfe85502260405180905060405180910390a17f47e2689743f14e97f7dcfa5eec10ba1dff02f83b3d1d4b9c07b206cbbda66450826040518082815260200191505060405180910390a1817fa48a6b249a5084126c3da369fbc9b16827ead8cb5cdc094b717d3f1dcd995e2960405180905060405180910390a27f7890603b316f3509577afd111710f9ebeefa15e12f72347d9dffd0d65ae3bade81604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390a18073ffffffffffffffffffffffffffffffffffffffff167f7efef9ea3f60ddc038e50cccec621f86a0195894dc0520482abf8b5c6b659e4160405180905060405180910390a28181604051808381526020018273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019250505060405180910390a05b5050565b6000600060008585859250925092505b935093509390505600a165627a7a72305820aaf842d0d0c35c45622c5263cbb54813d2974d3999c8c38551d7c613ea2bc1170029"),
//         nonce: 0,
//     });

//     let (evm, mut working_set) = get_evm(&config);
//     let l1_fee_rate = 1;

//     let deploy_message =
//         create_contract_message_with_fee(&dev_signer, 0, BlockHashContract::default(), 1);

//     let system_account = evm.accounts.get(&SYSTEM_SIGNER, &mut working_set);
//     assert!(
//         system_account.is_none(),
//         "There is no system account before call"
//     ); // That's optional but if the acc will exist in the future its balance must be zero.

//     evm.begin_soft_confirmation_hook(
//         [5u8; 32],
//         1,
//         [42u8; 32],
//         &[10u8; 32],
//         l1_fee_rate,
//         &mut working_set,
//     );
//     {
//         let sender_address = generate_address::<C>("sender");
//         let sequencer_address = generate_address::<C>("sequencer");
//         let context = C::new(sender_address, sequencer_address, 1);

//         evm.call(
//             CallMessage {
//                 txs: vec![deploy_message],
//             },
//             &context,
//             &mut working_set,
//         )
//         .unwrap();
//     }
//     evm.end_soft_confirmation_hook(&mut working_set);
//     evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

//     // let system_account = evm.accounts.get(&SYSTEM_SIGNER, &mut working_set).unwrap();
//     // // The system caller balance is unchanged(if exists)/or should be 0
//     // assert_eq!(system_account.info.balance, U256::from(0));
//     // assert_eq!(system_account.info.nonce, 1);

//     // let coinbase_account = evm.accounts.get(&config.coinbase, &mut working_set);
//     // assert!(coinbase_account.is_none());

//     assert_eq!(
//         evm.receipts
//             .iter(&mut working_set.accessory_state())
//             .collect::<Vec<_>>(),
//         [Receipt {
//             receipt: reth_primitives::Receipt {
//                 tx_type: reth_primitives::TxType::Eip1559,
//                 success: true,
//                 cumulative_gas_used: 114235,
//                 logs: vec![],
//             },
//             gas_used: 114235,
//             log_index_start: 0,
//             diff_size: 477,
//             error: None,
//         },]
//     )
// }
