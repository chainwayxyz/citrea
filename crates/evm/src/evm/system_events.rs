use reth_primitives::{
    address, Address, Bytes as RethBytes, Signature, Transaction, TransactionKind,
    TransactionSigned, TransactionSignedEcRecovered, TransactionSignedNoHash, TxEip1559, U256,
};

use super::system_contracts::L1BlockHashList;

/// This is a special signature to force tx.signer to be set to SYSTEM_SIGNER
pub const SYSTEM_SIGNATURE: Signature = Signature {
    r: U256::ZERO,
    s: U256::ZERO,
    odd_y_parity: false,
};

/// This is a special system address to indicate a tx is called by system not by a user/contract.
pub const SYSTEM_SIGNER: Address = address!("deaddeaddeaddeaddeaddeaddeaddeaddeaddead");

/// A system event is an event that is emitted on special conditions by the EVM.
/// There events will be transformed into Evm transactions and put in the begining of the block.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub(crate) enum SystemEvent {
    L1BlockHashInitialize(/*block number*/ u64),
    L1BlockHashSetBlockInfo(/*hash*/ [u8; 32], /*merkle root*/ [u8; 32]),
    BridgeInitialize(
        /*levels*/ u32,
        /*deposit script*/ Vec<u8>,
        /*script suffix*/ Vec<u8>,
        /*required sig count*/ U256,
    ),
    BridgeDeposit(
        /*version*/ [u8; 4],
        /*flag*/ [u8; 2],
        /*vin*/ Vec<u8>,
        /*vout*/ Vec<u8>,
        /*witness*/ Vec<u8>,
        /*locktime*/ [u8; 4],
        /*intermediate nodes*/ Vec<u8>,
        /*block height*/ ethereum_types::U256,
        /*index*/ ethereum_types::U256,
    ),
}

fn system_event_to_transaction(event: SystemEvent, nonce: u64, chain_id: u64) -> Transaction {
    let sys_block_hash = L1BlockHashList::default();
    let body: TxEip1559 = match event {
        SystemEvent::L1BlockHashInitialize(block_number) => TxEip1559 {
            to: TransactionKind::Call(L1BlockHashList::address()),
            input: RethBytes::from(sys_block_hash.init(block_number).to_vec()),
            nonce,
            chain_id,
            value: U256::ZERO,
            gas_limit: 1_000_000u64,
            max_fee_per_gas: u64::MAX as u128,
            ..Default::default()
        },
        SystemEvent::L1BlockHashSetBlockInfo(block_hash, txs_commitments) => TxEip1559 {
            to: TransactionKind::Call(L1BlockHashList::address()),
            input: RethBytes::from(
                sys_block_hash
                    .set_block_info(block_hash, txs_commitments)
                    .to_vec(),
            ),
            nonce,
            chain_id,
            value: U256::ZERO,
            gas_limit: 1_000_000u64,
            max_fee_per_gas: u64::MAX as u128,
            ..Default::default()
        },
        SystemEvent::BridgeInitialize(
            levels,
            deposit_script,
            script_suffix,
            required_sig_count,
        ) => TxEip1559 {
            to: TransactionKind::Call(L1BlockHashList::address()),
            input: RethBytes::from(sys_block_hash.init(block_number).to_vec()),
            nonce,
            chain_id,
            value: U256::ZERO,
            gas_limit: 1_000_000u64,
            max_fee_per_gas: u64::MAX as u128,
            ..Default::default()
        },
        SystemEvent::BridgeDeposit(
            version,
            flag,
            vin,
            vout,
            witness,
            locktime,
            intermediate_nodes,
            block_height,
            index,
        ) => TxEip1559 {
            to: TransactionKind::Call(L1BlockHashList::address()),
            input: RethBytes::from(
                sys_block_hash
                    .set_block_info(block_hash, txs_commitments)
                    .to_vec(),
            ),
            nonce,
            chain_id,
            value: U256::ZERO,
            gas_limit: 1_000_000u64,
            max_fee_per_gas: u64::MAX as u128,
            ..Default::default()
        },
    };
    Transaction::Eip1559(body)
}

fn signed_system_transaction(
    event: SystemEvent,
    nonce: u64,
    chain_id: u64,
) -> TransactionSignedEcRecovered {
    let transaction = system_event_to_transaction(event, nonce, chain_id);
    let signed_no_hash = TransactionSignedNoHash {
        signature: SYSTEM_SIGNATURE,
        transaction,
    };
    let signed: TransactionSigned = signed_no_hash.into();
    TransactionSignedEcRecovered::from_signed_transaction(signed, SYSTEM_SIGNER)
}

pub(crate) fn create_system_transactions<I: IntoIterator<Item = SystemEvent>>(
    events: I,
    mut nonce: u64,
    chain_id: u64,
) -> Vec<TransactionSignedEcRecovered> {
    events
        .into_iter()
        .map(|event| {
            let tx = signed_system_transaction(event, nonce, chain_id);
            nonce += 1;
            tx
        })
        .collect()
}
