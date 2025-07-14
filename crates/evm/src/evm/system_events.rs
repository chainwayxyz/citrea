use alloy_consensus::TxEip1559;
use alloy_primitives::{address, Address, PrimitiveSignature, TxKind, U256};
use reth_primitives::{Recovered, Transaction, TransactionSigned};

use super::system_contracts::{BitcoinLightClient, BridgeWrapper};

/// This is a special system address to indicate a tx is called by system not by a user/contract.
pub const SYSTEM_SIGNER: Address = address!("deaddeaddeaddeaddeaddeaddeaddeaddeaddead");

/// This is a special signature to force tx.signer to be set to SYSTEM_SIGNER
pub const SYSTEM_SIGNATURE: PrimitiveSignature =
    PrimitiveSignature::new(U256::ZERO, U256::ZERO, false);

/// A system event is an event that is emitted on special conditions by the EVM.
/// There events will be transformed into Evm transactions and put in the beginning of the block.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Eq, PartialEq)]
pub enum SystemEvent {
    /// Initializes the Bitcoin light client with the given block number.
    BitcoinLightClientInitialize(/*block number*/ u64),
    /// Sets the block info for the Bitcoin light client.
    BitcoinLightClientSetBlockInfo(
        /*hash*/ [u8; 32],
        /*merkle root*/ [u8; 32],
        /*coinbase depth*/ u64,
    ),
    /// Initializes the bridge contract.
    BridgeInitialize(
        /*script prefix, script suffix, deposit amount hex(abi()) */ Vec<u8>,
    ),
    /// Inserts deposit data to bridge contract.
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
        SystemEvent::BitcoinLightClientSetBlockInfo(
            block_hash,
            txs_commitments,
            coinbase_depth,
        ) => TxEip1559 {
            to: TxKind::Call(BitcoinLightClient::address()),
            input: BitcoinLightClient::set_block_info(block_hash, txs_commitments, coinbase_depth),
            nonce,
            chain_id,
            value: U256::ZERO,
            gas_limit: 1_000_000u64,
            max_fee_per_gas: u64::MAX as u128,
            ..Default::default()
        },
        SystemEvent::BridgeInitialize(params) => TxEip1559 {
            to: TxKind::Call(BridgeWrapper::address()),
            input: BridgeWrapper::initialize(params.as_slice()),
            nonce,
            chain_id,
            value: U256::ZERO,
            gas_limit: 1_000_000u64,
            max_fee_per_gas: u64::MAX as u128,
            ..Default::default()
        },
        SystemEvent::BridgeDeposit(params) => TxEip1559 {
            to: TxKind::Call(BridgeWrapper::address()),
            input: BridgeWrapper::deposit(params),
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

pub(crate) fn signed_system_transaction(
    event: SystemEvent,
    nonce: u64,
    chain_id: u64,
) -> Recovered<TransactionSigned> {
    let transaction = system_event_to_transaction(event, nonce, chain_id);
    let signed_no_hash = TransactionSigned::new_unhashed(transaction, SYSTEM_SIGNATURE);
    Recovered::new_unchecked(signed_no_hash, SYSTEM_SIGNER)
}

/// Creates a list of system transactions from a list of system events.
pub fn create_system_transactions<I: IntoIterator<Item = SystemEvent>>(
    events: I,
    mut nonce: u64,
    chain_id: u64,
) -> Vec<Recovered<TransactionSigned>> {
    events
        .into_iter()
        .map(|event| {
            let tx = signed_system_transaction(event, nonce, chain_id);
            nonce += 1;
            tx
        })
        .collect()
}
