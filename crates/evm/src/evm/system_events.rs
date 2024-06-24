use reth_primitives::{
    address, Address, Signature, Transaction, TransactionSigned, TransactionSignedEcRecovered,
    TransactionSignedNoHash, TxEip1559, TxKind, U256,
};

use super::system_contracts::{BitcoinLightClient, Bridge};

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
    BitcoinLightClientInitialize(/*block number*/ u64),
    BitcoinLightClientSetBlockInfo(/*hash*/ [u8; 32], /*merkle root*/ [u8; 32]),
    BridgeInitialize,
    BridgeDeposit(Vec<u8>), // version, flag, vin, vout, witness, locktime, intermediate nodes, block height, index
}

fn system_event_to_transaction(event: SystemEvent, nonce: u64, chain_id: u64) -> Transaction {
    let body: TxEip1559 = match event {
        SystemEvent::BitcoinLightClientInitialize(block_number) => TxEip1559 {
            to: TxKind::Call(BitcoinLightClient::address()),
            input: BitcoinLightClient::init(block_number),
            nonce,
            chain_id,
            value: U256::ZERO,
            gas_limit: 1_000_000u64,
            max_fee_per_gas: u64::MAX as u128,
            ..Default::default()
        },
        SystemEvent::BitcoinLightClientSetBlockInfo(block_hash, txs_commitments) => TxEip1559 {
            to: TxKind::Call(BitcoinLightClient::address()),
            input: BitcoinLightClient::set_block_info(block_hash, txs_commitments),
            nonce,
            chain_id,
            value: U256::ZERO,
            gas_limit: 1_000_000u64,
            max_fee_per_gas: u64::MAX as u128,
            ..Default::default()
        },
        SystemEvent::BridgeInitialize => TxEip1559 {
            to: TxKind::Call(Bridge::address()),
            input: Bridge::initialize(),
            nonce,
            chain_id,
            value: U256::ZERO,
            gas_limit: 1_000_000u64,
            max_fee_per_gas: u64::MAX as u128,
            ..Default::default()
        },
        SystemEvent::BridgeDeposit(params) => TxEip1559 {
            to: TxKind::Call(Bridge::address()),
            input: Bridge::deposit(params),
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
