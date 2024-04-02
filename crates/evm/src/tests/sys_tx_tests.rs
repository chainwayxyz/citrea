use std::str::FromStr;

use reth_primitives::{address, b256, hex, Log};
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
use crate::{AccountData, SystemEvent, SYSTEM_SIGNER};

type C = DefaultContext;

#[test]
fn test_sys_l1blockhashlist() {
    let (mut config, dev_signer, _) =
        get_evm_config_starting_base_fee(U256::from_str("1000000").unwrap(), None, 1);

    config.data.push(AccountData {
        address: address!("3100000000000000000000000000000000000001"),
        balance: U256::ZERO,
        code_hash: b256!("3910ced36f7b080ceb008e6ec62b2af85c83c215fc26c1d6c084bfce0d20e5fd"),
        code: Bytes::from_static(&hex!("608060405234801561001057600080fd5b50600436106100cf5760003560e01c806379ba50971161008c578063e30c397811610066578063e30c3978146101c0578063ee82ac5e146101d3578063f2fde38b146101f3578063fe5a53771461020657600080fd5b806379ba50971461016d5780638da5cb5b14610175578063be7d4fb1146101a057600080fd5b80630e27bc11146100d45780631f578333146100e957806334cdf78d146100fc5780633dc090b31461012f57806357e871e71461015c578063715018a614610165575b600080fd5b6100e76100e2366004610550565b610226565b005b6100e76100f7366004610572565b610319565b61011c61010a366004610572565b60026020526000908152604090205481565b6040519081526020015b60405180910390f35b61011c61013d366004610572565b6000908152600260209081526040808320548352600390915290205490565b61011c60045481565b6100e761038e565b6100e7610404565b600054610188906001600160a01b031681565b6040516001600160a01b039091168152602001610126565b61011c6101ae366004610572565b60009081526003602052604090205490565b600154610188906001600160a01b031681565b61011c6101e1366004610572565b60009081526002602052604090205490565b6100e761020136600461058b565b6104ca565b61011c610214366004610572565b60036020526000908152604090205481565b6000546001600160a01b031633146102595760405162461bcd60e51b8152600401610250906105bb565b60405180910390fd5b600454600081900361029f5760405162461bcd60e51b815260206004820152600f60248201526e139bdd081a5b9a5d1a585b1a5e9959608a1b6044820152606401610250565b60008181526002602052604090208390556102bb8160016105e8565b60049081556000848152600360209081526040918290208590559154815190815291820185905281018390527f32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f9060600160405180910390a1505050565b6000546001600160a01b031633146103435760405162461bcd60e51b8152600401610250906105bb565b600454156103895760405162461bcd60e51b8152602060048201526013602482015272105b1c9958591e481a5b9a5d1a585b1a5e9959606a1b6044820152606401610250565b600455565b6000546001600160a01b031633146103b85760405162461bcd60e51b8152600401610250906105bb565b600080546001600160a01b03191681556040805182815260208101929092527f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0910160405180910390a1565b6001546001600160a01b0316331461045e5760405162461bcd60e51b815260206004820152601b60248201527f43616c6c6572206973206e6f742070656e64696e67206f776e657200000000006044820152606401610250565b60008054600180546001600160a01b03198084166001600160a01b038084169190911786559116909155604080519190921680825260208201939093527f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e091015b60405180910390a150565b6000546001600160a01b031633146104f45760405162461bcd60e51b8152600401610250906105bb565b600180546001600160a01b0319166001600160a01b038381169182179092556000546040805191909316815260208101919091527fed8889f560326eb138920d842192f0eb3dd22b4f139c87a2c57538e05bae127891016104bf565b6000806040838503121561056357600080fd5b50508035926020909101359150565b60006020828403121561058457600080fd5b5035919050565b60006020828403121561059d57600080fd5b81356001600160a01b03811681146105b457600080fd5b9392505050565b60208082526013908201527221b0b63632b91034b9903737ba1037bbb732b960691b604082015260600190565b8082018082111561060957634e487b7160e01b600052601160045260246000fd5b9291505056fea26469706673582212205dfa4db05d69b0ec5242ffb4b3b1827ebae2a2d822480dd81d73892aca15054264736f6c63430008190033")),
        nonce: 0,
        storage: [
            (U256::from_be_slice(&hex!("0000000000000000000000000000000000000000000000000000000000000000")), U256::from_be_slice(SYSTEM_SIGNER.into_word().as_slice())),
            (U256::from_be_slice(&hex!("6661e9d6d8b923d5bbaab1b96e1dd51ff6ea2a93520fdc9eb75d059238b8c5e9")), U256::from(1))
        ].into_iter().collect(),
    });

    let (evm, mut working_set) = get_evm(&config);

    let system_events: Vec<_> = evm.system_events.iter(&mut working_set).collect();
    assert_eq!(
        system_events,
        vec![
            SystemEvent::L1BlockHashInitialize(1),
            SystemEvent::L1BlockHashSetBlockInfo([1; 32], [2; 32])
        ],
        "System events must be produced in the get_evm() call"
    );

    let l1_fee_rate = 1;

    let deploy_message =
        create_contract_message_with_fee(&dev_signer, 0, BlockHashContract::default(), 1);

    let system_account = evm.accounts.get(&SYSTEM_SIGNER, &mut working_set);
    assert!(
        system_account.is_none(),
        "There is no system account before call"
    ); // That's optional but if the acc will exist in the future its balance must be zero.

    evm.begin_soft_confirmation_hook(
        [1u8; 32],
        1,
        [2u8; 32],
        &[10u8; 32],
        l1_fee_rate,
        &mut working_set,
    );
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

        let system_events: Vec<_> = evm.system_events.iter(&mut working_set).collect();
        assert!(
            system_events.is_empty(),
            "System events must be empty after evm.call()"
        );
    }
    evm.end_soft_confirmation_hook(&mut working_set);
    evm.finalize_hook(&[99u8; 32].into(), &mut working_set.accessory_state());

    let system_account = evm.accounts.get(&SYSTEM_SIGNER, &mut working_set).unwrap();
    // The system caller balance is unchanged(if exists)/or should be 0
    assert_eq!(system_account.info.balance, U256::from(0));
    assert_eq!(system_account.info.nonce, 0);

    assert_eq!(
        evm.receipts
            .iter(&mut working_set.accessory_state())
            .collect::<Vec<_>>(),
        [
            Receipt { // L1BlockHashList::initializeBlockNumber(U256)
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 45711,
                    logs: vec![]
                },
                gas_used: 45711,
                log_index_start: 0,
                diff_size: 284,
                error: None
            },
            Receipt { // L1BlockHashList::setBlockInfo(U256, U256)
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 121376,
                    logs: vec![
                        Log {
                            address: L1BlockHashList::address(),
                            topics: vec![b256!("32eff959e2e8d1609edc4b39ccf75900aa6c1da5719f8432752963fdf008234f")],
                            data: Bytes::from_static(&hex!("000000000000000000000000000000000000000000000000000000000000000201010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202")),
                        }
                    ]
                },
                gas_used: 75665,
                log_index_start: 0,
                diff_size: 412,
                error: None
            },
            Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: reth_primitives::TxType::Eip1559,
                    success: true,
                    cumulative_gas_used: 235611,
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

    evm.begin_soft_confirmation_hook(
        [2u8; 32],
        2,
        [3u8; 32],
        &[10u8; 32],
        l1_fee_rate,
        &mut working_set,
    );

    let system_events: Vec<_> = evm.system_events.iter(&mut working_set).collect();
    assert_eq!(
        system_events,
        vec![SystemEvent::L1BlockHashSetBlockInfo([2; 32], [3; 32])],
        "System event must be produced in the begin_soft_confirmation_hook() call"
    );
}
