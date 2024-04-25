use std::collections::HashMap;
use std::str::FromStr;

use reth_primitives::constants::ETHEREUM_BLOCK_GAS_LIMIT;
use reth_primitives::{b256, hex, BlockNumberOrTag, Log};
use reth_rpc_types::{TransactionInput, TransactionRequest};
use revm::primitives::{Bytes, U256};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::utils::generate_address;
use sov_modules_api::{Context, Module, StateMapAccessor, StateVecAccessor};

use crate::call::CallMessage;
use crate::evm::primitive_types::Receipt;
use crate::evm::system_contracts::L1BlockHashList;
use crate::smart_contracts::{BlockHashContract, LogsContract};
use crate::tests::call_tests::{
    create_contract_message, create_contract_message_with_fee, get_evm_config_starting_base_fee,
    publish_event_message,
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
        Bytes::from_static(&hex!("608060405234801561001057600080fd5b50600436106100a95760003560e01c806357e871e71161007157806357e871e71461014c57806361b207e214610155578063a91d8b3d14610182578063d269a03e146101a2578063d761753e146101b5578063ee82ac5e146101e857600080fd5b80630466efc4146100ae5780630e27bc11146100e15780631f578333146100f657806334cdf78d146101095780634ffd344a14610129575b600080fd5b6100ce6100bc366004610599565b60009081526002602052604090205490565b6040519081526020015b60405180910390f35b6100f46100ef3660046105b2565b610208565b005b6100f4610104366004610599565b610331565b6100ce610117366004610599565b60016020526000908152604090205481565b61013c61013736600461061d565b6103df565b60405190151581526020016100d8565b6100ce60005481565b6100ce610163366004610599565b6000908152600160209081526040808320548352600290915290205490565b6100ce610190366004610599565b60026020526000908152604090205481565b61013c6101b036600461061d565b610405565b6101d073deaddeaddeaddeaddeaddeaddeaddeaddeaddead81565b6040516001600160a01b0390911681526020016100d8565b6100ce6101f6366004610599565b60009081526001602052604090205490565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146102705760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c65720060448201526064015b60405180910390fd5b60008054908190036102b65760405162461bcd60e51b815260206004820152600f60248201526e139bdd081a5b9a5d1a585b1a5e9959608a1b6044820152606401610267565b60008181526001602081905260409091208490556102d5908290610678565b6000908155838152600260209081526040808320859055915482519081529081018590529081018390527f32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f9060600160405180910390a1505050565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146103945760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c6572006044820152606401610267565b600054156103da5760405162461bcd60e51b8152602060048201526013602482015272105b1c9958591e481a5b9a5d1a585b1a5e9959606a1b6044820152606401610267565b600055565b6000858152600160205260408120546103fb9086868686610410565b9695505050505050565b60006103fb86868686865b6000858152600260209081526040808320548151601f870184900484028101840190925285825291610463918891849190899089908190840183828082843760009201919091525089925061046e915050565b979650505050505050565b6000838514801561047d575081155b801561048857508251155b15610495575060016104a4565b6104a1858486856104ac565b90505b949350505050565b6000602084516104bc9190610699565b156104c9575060006104a4565b83516000036104da575060006104a4565b818560005b8651811015610549576104f3600284610699565b6001036105175761051061050a8883016020015190565b83610556565b9150610530565b61052d826105288984016020015190565b610556565b91505b60019290921c91610542602082610678565b90506104df565b5090931495945050505050565b6000610562838361056b565b90505b92915050565b60008260005281602052602060006040600060025afa50602060006020600060025afa505060005192915050565b6000602082840312156105ab57600080fd5b5035919050565b600080604083850312156105c557600080fd5b50508035926020909101359150565b60008083601f8401126105e657600080fd5b50813567ffffffffffffffff8111156105fe57600080fd5b60208301915083602082850101111561061657600080fd5b9250929050565b60008060008060006080868803121561063557600080fd5b8535945060208601359350604086013567ffffffffffffffff81111561065a57600080fd5b610666888289016105d4565b96999598509660600135949350505050565b8082018082111561056557634e487b7160e01b600052601160045260246000fd5b6000826106b657634e487b7160e01b600052601260045260246000fd5b50069056fea26469706673582212203f38cf5ee903bac8d195ec0eca1aa029b26a4571354479e22036d9625b2c509764736f6c63430008190033")),
        HashMap::new()
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
                    cumulative_gas_used: 43615,
                    logs: vec![]
                },
                gas_used: 43615,
                log_index_start: 0,
                diff_size: 220,
            },
            Receipt { // L1BlockHashList::setBlockInfo(U256, U256)
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 117196,
                    logs: vec![
                        Log {
                            address: L1BlockHashList::address(),
                            topics: vec![b256!("32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f")],
                            data: Bytes::from_static(&hex!("000000000000000000000000000000000000000000000000000000000000000201010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202")),
                        }
                    ]
                },
                gas_used: 73581,
                log_index_start: 0,
                diff_size: 348,
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
                    cumulative_gas_used: 73581,
                    logs: vec![
                        Log {
                            address: L1BlockHashList::address(),
                            topics: vec![b256!("32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f")],
                            data: Bytes::from_static(&hex!("000000000000000000000000000000000000000000000000000000000000000302020202020202020202020202020202020202020202020202020202020202020303030303030303030303030303030303030303030303030303030303030303")),
                        }
                    ]
                },
                gas_used: 73581,
                log_index_start: 0,
                diff_size: 348,
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 187816,
                    logs: vec![]
                },
                gas_used: 114235,
                log_index_start: 1,
                diff_size: 477,
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

#[test]
fn test_sys_tx_gas_usage_effect_on_block_gas_limit() {
    // This test also tests evm checking gas usage and not just the tx gas limit when including txs in block after checking available block limit
    // For example txs below have 1_000_000 gas limit, the block used to stuck at 29_030_000 gas usage but now can utilize the whole block gas limit
    let (mut config, dev_signer, contract_addr) = get_evm_config_starting_base_fee(
        U256::from_str("100000000000000000000").unwrap(),
        Some(ETHEREUM_BLOCK_GAS_LIMIT),
        1,
    );

    config.data.push(AccountData::new(
        L1BlockHashList::address(),
        U256::ZERO,
        Bytes::from_static(&hex!("608060405234801561001057600080fd5b50600436106100a95760003560e01c806357e871e71161007157806357e871e71461014c57806361b207e214610155578063a91d8b3d14610182578063d269a03e146101a2578063d761753e146101b5578063ee82ac5e146101e857600080fd5b80630466efc4146100ae5780630e27bc11146100e15780631f578333146100f657806334cdf78d146101095780634ffd344a14610129575b600080fd5b6100ce6100bc366004610599565b60009081526002602052604090205490565b6040519081526020015b60405180910390f35b6100f46100ef3660046105b2565b610208565b005b6100f4610104366004610599565b610331565b6100ce610117366004610599565b60016020526000908152604090205481565b61013c61013736600461061d565b6103df565b60405190151581526020016100d8565b6100ce60005481565b6100ce610163366004610599565b6000908152600160209081526040808320548352600290915290205490565b6100ce610190366004610599565b60026020526000908152604090205481565b61013c6101b036600461061d565b610405565b6101d073deaddeaddeaddeaddeaddeaddeaddeaddeaddead81565b6040516001600160a01b0390911681526020016100d8565b6100ce6101f6366004610599565b60009081526001602052604090205490565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146102705760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c65720060448201526064015b60405180910390fd5b60008054908190036102b65760405162461bcd60e51b815260206004820152600f60248201526e139bdd081a5b9a5d1a585b1a5e9959608a1b6044820152606401610267565b60008181526001602081905260409091208490556102d5908290610678565b6000908155838152600260209081526040808320859055915482519081529081018590529081018390527f32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f9060600160405180910390a1505050565b3373deaddeaddeaddeaddeaddeaddeaddeaddeaddead146103945760405162461bcd60e51b815260206004820152601f60248201527f63616c6c6572206973206e6f74207468652073797374656d2063616c6c6572006044820152606401610267565b600054156103da5760405162461bcd60e51b8152602060048201526013602482015272105b1c9958591e481a5b9a5d1a585b1a5e9959606a1b6044820152606401610267565b600055565b6000858152600160205260408120546103fb9086868686610410565b9695505050505050565b60006103fb86868686865b6000858152600260209081526040808320548151601f870184900484028101840190925285825291610463918891849190899089908190840183828082843760009201919091525089925061046e915050565b979650505050505050565b6000838514801561047d575081155b801561048857508251155b15610495575060016104a4565b6104a1858486856104ac565b90505b949350505050565b6000602084516104bc9190610699565b156104c9575060006104a4565b83516000036104da575060006104a4565b818560005b8651811015610549576104f3600284610699565b6001036105175761051061050a8883016020015190565b83610556565b9150610530565b61052d826105288984016020015190565b610556565b91505b60019290921c91610542602082610678565b90506104df565b5090931495945050505050565b6000610562838361056b565b90505b92915050565b60008260005281602052602060006040600060025afa50602060006020600060025afa505060005192915050565b6000602082840312156105ab57600080fd5b5035919050565b600080604083850312156105c557600080fd5b50508035926020909101359150565b60008083601f8401126105e657600080fd5b50813567ffffffffffffffff8111156105fe57600080fd5b60208301915083602082850101111561061657600080fd5b9250929050565b60008060008060006080868803121561063557600080fd5b8535945060208601359350604086013567ffffffffffffffff81111561065a57600080fd5b610666888289016105d4565b96999598509660600135949350505050565b8082018082111561056557634e487b7160e01b600052601160045260246000fd5b6000826106b657634e487b7160e01b600052601260045260246000fd5b50069056fea26469706673582212203f38cf5ee903bac8d195ec0eca1aa029b26a4571354479e22036d9625b2c509764736f6c63430008190033")),
        HashMap::new()
    ));

    let (evm, mut working_set) = get_evm(&config);
    let l1_fee_rate = 0;

    let sender_address = generate_address::<C>("sender");
    let sequencer_address = generate_address::<C>("sequencer");
    let context = C::new(sender_address, sequencer_address, 1);

    evm.begin_soft_confirmation_hook(
        [5u8; 32],
        1,
        [42u8; 32],
        &[10u8; 32],
        l1_fee_rate,
        0,
        &mut working_set,
    );
    {
        // deploy logs contract
        evm.call(
            CallMessage {
                txs: vec![create_contract_message(
                    &dev_signer,
                    0,
                    LogsContract::default(),
                )],
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    evm.begin_soft_confirmation_hook(
        [10u8; 32],
        2,
        [43u8; 32],
        &[10u8; 32],
        l1_fee_rate,
        0,
        &mut working_set,
    );
    {
        let context = C::new(sender_address, sequencer_address, 2);

        let sys_tx_gas_usage = evm.get_pending_txs_cumulative_gas_used(&mut working_set);
        assert_eq!(sys_tx_gas_usage, 73581);

        let mut rlp_transactions = Vec::new();

        // the amount of gas left is 30_000_000 - 73581 = 29926419
        // send barely enough gas to reach the limit
        // one publish event message is 26388 gas
        // 29926419 / 26388 = 1134.09
        // so there cannot be more than 1134 messages
        for i in 0..11350 {
            rlp_transactions.push(publish_event_message(
                contract_addr,
                &dev_signer,
                i + 1,
                "hello".to_string(),
            ));
        }

        evm.call(
            CallMessage {
                txs: rlp_transactions,
            },
            &context,
            &mut working_set,
        )
        .unwrap();
    }
    evm.end_soft_confirmation_hook(&mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let block = evm
        .get_block_by_number(Some(BlockNumberOrTag::Latest), None, &mut working_set)
        .unwrap()
        .unwrap();

    assert_eq!(block.header.gas_limit, U256::from(ETHEREUM_BLOCK_GAS_LIMIT));
    assert!(block.header.gas_used <= block.header.gas_limit);

    // In total there should only be 1135 transactions 1 is system tx others are contract calls
    assert!(
        block.transactions.hashes().len() == 1135,
        "Some transactions should be dropped because of gas limit"
    );
}
