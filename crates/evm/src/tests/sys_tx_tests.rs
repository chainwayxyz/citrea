use std::str::FromStr;

use reth_primitives::{b256, hex, Log};
use reth_rpc_types::{TransactionInput, TransactionRequest};
use revm::primitives::{Bytes, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, StateMapAccessor, StateVecAccessor};

use crate::call::CallMessage;
use crate::evm::primitive_types::Receipt;
use crate::evm::system_contracts::L1BlockHashList;
use crate::smart_contracts::BlockHashContract;
use crate::tests::call_tests::{
    create_contract_message_with_fee, get_evm_config_starting_base_fee,
};
use crate::tests::genesis_tests::get_evm;
use crate::{AccountData, SYSTEM_SIGNER};

type C = DefaultContext;

#[test]
fn test_sys_l1blockhashlist() {
    let (mut config, dev_signer, _) =
        get_evm_config_starting_base_fee(U256::from_str("1000000").unwrap(), None, 1);

    config.data.push(AccountData::new(
        L1BlockHashList::address(),
        U256::ZERO,
        Bytes::from_static(&hex!("608060405234801561001057600080fd5b50600436106100f55760003560e01c8063715018a611610097578063d269a03e11610066578063d269a03e14610229578063e30c39781461023c578063ee82ac5e1461024f578063f2fde38b1461026f57600080fd5b8063715018a6146101ce57806379ba5097146101d65780638da5cb5b146101de578063a91d8b3d1461020957600080fd5b806334cdf78d116100d357806334cdf78d146101555780634ffd344a1461017557806357e871e71461019857806361b207e2146101a157600080fd5b80630466efc4146100fa5780630e27bc111461012d5780631f57833314610142575b600080fd5b61011a61010836600461076a565b60009081526003602052604090205490565b6040519081526020015b60405180910390f35b61014061013b366004610783565b610282565b005b61014061015036600461076a565b610375565b61011a61016336600461076a565b60026020526000908152604090205481565b6101886101833660046107ee565b6103ea565b6040519015158152602001610124565b61011a60045481565b61011a6101af36600461076a565b6000908152600260209081526040808320548352600390915290205490565b610140610410565b610140610486565b6000546101f1906001600160a01b031681565b6040516001600160a01b039091168152602001610124565b61011a61021736600461076a565b60036020526000908152604090205481565b6101886102373660046107ee565b61054c565b6001546101f1906001600160a01b031681565b61011a61025d36600461076a565b60009081526002602052604090205490565b61014061027d366004610849565b61055b565b6000546001600160a01b031633146102b55760405162461bcd60e51b81526004016102ac90610879565b60405180910390fd5b60045460008190036102fb5760405162461bcd60e51b815260206004820152600f60248201526e139bdd081a5b9a5d1a585b1a5e9959608a1b60448201526064016102ac565b60008181526002602052604090208390556103178160016108a6565b60049081556000848152600360209081526040918290208590559154815190815291820185905281018390527f32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f9060600160405180910390a1505050565b6000546001600160a01b0316331461039f5760405162461bcd60e51b81526004016102ac90610879565b600454156103e55760405162461bcd60e51b8152602060048201526013602482015272105b1c9958591e481a5b9a5d1a585b1a5e9959606a1b60448201526064016102ac565b600455565b60008581526002602052604081205461040690868686866105e1565b9695505050505050565b6000546001600160a01b0316331461043a5760405162461bcd60e51b81526004016102ac90610879565b600080546001600160a01b03191681556040805182815260208101929092527f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0910160405180910390a1565b6001546001600160a01b031633146104e05760405162461bcd60e51b815260206004820152601b60248201527f43616c6c6572206973206e6f742070656e64696e67206f776e6572000000000060448201526064016102ac565b60008054600180546001600160a01b03198084166001600160a01b038084169190911786559116909155604080519190921680825260208201939093527f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e091015b60405180910390a150565b600061040686868686866105e1565b6000546001600160a01b031633146105855760405162461bcd60e51b81526004016102ac90610879565b600180546001600160a01b0319166001600160a01b038381169182179092556000546040805191909316815260208101919091527fed8889f560326eb138920d842192f0eb3dd22b4f139c87a2c57538e05bae12789101610541565b6000858152600360209081526040808320548151601f870184900484028101840190925285825291610634918891849190899089908190840183828082843760009201919091525089925061063f915050565b979650505050505050565b6000838514801561064e575081155b801561065957508251155b1561066657506001610675565b6106728584868561067d565b90505b949350505050565b60006020845161068d91906108c7565b1561069a57506000610675565b83516000036106ab57506000610675565b818560005b865181101561071a576106c46002846108c7565b6001036106e8576106e16106db8883016020015190565b83610727565b9150610701565b6106fe826106f98984016020015190565b610727565b91505b60019290921c916107136020826108a6565b90506106b0565b5090931495945050505050565b6000610733838361073c565b90505b92915050565b60008260005281602052602060006040600060025afa50602060006020600060025afa505060005192915050565b60006020828403121561077c57600080fd5b5035919050565b6000806040838503121561079657600080fd5b50508035926020909101359150565b60008083601f8401126107b757600080fd5b50813567ffffffffffffffff8111156107cf57600080fd5b6020830191508360208285010111156107e757600080fd5b9250929050565b60008060008060006080868803121561080657600080fd5b8535945060208601359350604086013567ffffffffffffffff81111561082b57600080fd5b610837888289016107a5565b96999598509660600135949350505050565b60006020828403121561085b57600080fd5b81356001600160a01b038116811461087257600080fd5b9392505050565b60208082526013908201527221b0b63632b91034b9903737ba1037bbb732b960691b604082015260600190565b8082018082111561073657634e487b7160e01b600052601160045260246000fd5b6000826108e457634e487b7160e01b600052601260045260246000fd5b50069056fea264697066735822122047f87b69f6257337195f178a4f126d7bc4b6097397b529282027d5c023c891e764736f6c63430008190033")),
        [
             (U256::from_be_slice(&hex!("0000000000000000000000000000000000000000000000000000000000000000")), U256::from_be_slice(SYSTEM_SIGNER.into_word().as_slice())),
        ].into_iter().collect()
    ));

    let (evm, mut working_set) = get_evm(&config);

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [
            Receipt { // L1BlockHashList::initializeBlockNumber(U256)
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 45756,
                    logs: vec![]
                },
                gas_used: 45756,
                log_index_start: 0,
                diff_size: 284,
                error: None
            },
            Receipt { // L1BlockHashList::setBlockInfo(U256, U256)
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 121466,
                    logs: vec![
                        Log {
                            address: L1BlockHashList::address(),
                            topics: vec![b256!("32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f")],
                            data: Bytes::from_static(&hex!("000000000000000000000000000000000000000000000000000000000000000201010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202")),
                        }
                    ]
                },
                gas_used: 75710,
                log_index_start: 0,
                diff_size: 412,
                error: None
            },
        ]
    );

    let l1_fee_rate = 1;

    let system_account = evm.accounts.get(&SYSTEM_SIGNER, &mut working_set).unwrap();
    // The system caller balance is unchanged(if exists)/or should be 0
    assert_eq!(system_account.info.balance, U256::from(0));
    assert_eq!(system_account.info.nonce, 2);

    let hash = evm
        .get_call(
            TransactionRequest {
                to: Some(L1BlockHashList::address()),
                input: TransactionInput::new(L1BlockHashList::get_block_hash(1)),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    let merkle_root = evm
        .get_call(
            TransactionRequest {
                to: Some(L1BlockHashList::address()),
                input: TransactionInput::new(L1BlockHashList::get_witness_root_by_number(1)),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    assert_eq!(hash.as_ref(), &[1u8; 32]);
    assert_eq!(merkle_root.as_ref(), &[2u8; 32]);

    // New L1 block №2
    evm.begin_soft_confirmation_hook(
        [2u8; 32],
        2,
        [3u8; 32],
        &[10u8; 32],
        l1_fee_rate,
        42,
        &mut working_set,
    );
    {
        let sender_address = generate_address::<C>("sender");
        let sequencer_address = generate_address::<C>("sequencer");
        let context = C::new(sender_address, sequencer_address, 1);

        let deploy_message =
            create_contract_message_with_fee(&dev_signer, 0, BlockHashContract::default(), 1);

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
    assert_eq!(system_account.info.nonce, 3);

    let receipts: Vec<_> = evm
        .receipts
        .iter(&mut working_set.accessory_state())
        .collect();
    assert_eq!(receipts.len(), 4); // 2 from #1 L1 block and 2 from #2 block
    let receipts = receipts[2..].to_vec();

    assert_eq!(receipts,
        [
            Receipt { // L1BlockHashList::setBlockInfo(U256, U256)
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 75710,
                    logs: vec![
                        Log {
                            address: L1BlockHashList::address(),
                            topics: vec![b256!("32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f")],
                            data: Bytes::from_static(&hex!("000000000000000000000000000000000000000000000000000000000000000302020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303")),
                        }
                    ]
                },
                gas_used: 75710,
                log_index_start: 0,
                diff_size: 412,
                error: None
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 189945,
                    logs: vec![]
                },
                gas_used: 114235,
                log_index_start: 1,
                diff_size: 477,
                error: None
            }
        ]
    );

    let coinbase_account = evm
        .accounts
        .get(&config.coinbase, &mut working_set)
        .unwrap();
    assert_eq!(coinbase_account.info.balance, U256::from(114235 + 477));

    let hash = evm
        .get_call(
            TransactionRequest {
                to: Some(L1BlockHashList::address()),
                input: TransactionInput::new(L1BlockHashList::get_block_hash(2)),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    let merkle_root = evm
        .get_call(
            TransactionRequest {
                to: Some(L1BlockHashList::address()),
                input: TransactionInput::new(L1BlockHashList::get_witness_root_by_number(2)),
                ..Default::default()
            },
            None,
            None,
            None,
            &mut working_set,
        )
        .unwrap();

    assert_eq!(hash.as_ref(), &[2u8; 32]);
    assert_eq!(merkle_root.as_ref(), &[3u8; 32]);
}
