use std::str::FromStr;

use alloy::consensus::{SignableTransaction, TxEnvelope};
use alloy::providers::network::TxSignerSync;
use alloy::signers::local::PrivateKeySigner;
use alloy_rlp::{Decodable, Encodable};
use bytes::BytesMut;
use reth_primitives::{
    Address, Bytes, TransactionSigned, TransactionSignedEcRecovered, TxKind, U256,
};
use reth_rpc_types::request::{TransactionInput, TransactionRequest};
use revm::primitives::{TransactTo, TxEnv};

use crate::evm::call::create_txn_env;
use crate::evm::primitive_types::TransactionSignedAndRecovered;
use crate::primitive_types::{Block, BlockEnv};
use crate::tests::DEFAULT_CHAIN_ID;

#[test]
fn tx_rlp_encoding_test() {
    let wallet = "dcf2cbdd171a21c480aa7f53d77f31bb102282b3ff099c78e3118b37348c72f7"
        .parse::<PrivateKeySigner>()
        .unwrap();
    let from_addr = wallet.address();
    let to_addr = Address::from_str("0x0aa7420c43b8c1a7b165d216948870c8ecfe1ee1").unwrap();
    let data: Bytes = Bytes::from_str(
        "0x6ecd23060000000000000000000000000000000000000000000000000000000000000002",
    )
    .unwrap();

    let mut request = TransactionRequest::default()
        .from(from_addr)
        .nonce(0u64)
        .max_priority_fee_per_gas(413047990155)
        .max_fee_per_gas(768658734568)
        .gas_limit(184156)
        .to(to_addr)
        .value(U256::from(2000000000000u64))
        .input(data.into());
    request.chain_id = Some(DEFAULT_CHAIN_ID);

    let typed_tx = request.build_typed_tx().unwrap();
    let mut tx = typed_tx.eip1559().unwrap().clone();

    let sig = wallet.sign_transaction_sync(&mut tx).unwrap();
    let addr = sig
        .recover_address_from_prehash(&tx.signature_hash())
        .unwrap();
    assert_eq!(addr, wallet.address());

    let sig = sig.with_parity_bool(); // drop signature.v so the hash of tx is calculated correctly
    let signed = tx.into_signed(sig);
    let envelope: TxEnvelope = signed.into();

    let mut bytes = BytesMut::new();
    envelope.encode(&mut bytes);

    let decoded = TransactionSigned::decode(&mut bytes.as_ref()).unwrap();

    let decoded_signed = decoded.try_ecrecovered().unwrap();
    let decoded_signer = decoded_signed.signer();
    assert_eq!(decoded_signer, wallet.address());

    let decoded_envelope = TxEnvelope::decode(&mut bytes.as_ref()).unwrap();
    assert_eq!(envelope, decoded_envelope);
}

#[test]
fn tx_conversion() {
    let signer = Address::random();
    let tx = TransactionSignedAndRecovered {
        signer,
        signed_transaction: reth_primitives::TransactionSigned {
            hash: Default::default(),
            signature: Default::default(),
            transaction: Default::default(),
        },
        block_number: 5u64,
    };

    let reth_tx: TransactionSignedEcRecovered = tx.into();

    assert_eq!(signer, reth_tx.signer());
}

// TODO: Needs more complex tests later
#[test]
fn prepare_call_env_conversion() {
    let from = Address::random();
    let to = Address::random();
    let request = TransactionRequest {
        from: Some(from),
        to: Some(TxKind::Call(to)),
        gas_price: Some(100),
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        gas: Some(200),
        value: Some(U256::from(300u64)),
        input: TransactionInput::default(),
        nonce: Some(1u64),
        chain_id: Some(1u64),
        access_list: None,
        transaction_type: Some(2u8),
        blob_versioned_hashes: None,
        max_fee_per_blob_gas: None,
        sidecar: None,
    };

    let block_env = BlockEnv::default();

    let tx_env = create_txn_env(&block_env, request, None).unwrap();
    let expected = TxEnv {
        caller: from,
        gas_price: U256::from(100u64),
        gas_limit: 200u64,
        gas_priority_fee: None,
        transact_to: TransactTo::Call(to),
        value: U256::from(300u64),
        data: Default::default(),
        chain_id: Some(1u64),
        nonce: Some(1u64),
        access_list: vec![],
        blob_hashes: vec![],
        max_fee_per_blob_gas: None,
        authorization_list: None,
    };

    assert_eq!(tx_env.caller, expected.caller);
    assert_eq!(tx_env.gas_limit, expected.gas_limit);
    assert_eq!(tx_env.gas_price, expected.gas_price);
    assert_eq!(tx_env.gas_priority_fee, expected.gas_priority_fee);
    assert_eq!(
        tx_env.transact_to.is_create(),
        expected.transact_to.is_create()
    );
    assert_eq!(tx_env.value, expected.value);
    assert_eq!(tx_env.data, expected.data);
    assert_eq!(tx_env.chain_id, expected.chain_id);
    assert_eq!(tx_env.nonce, expected.nonce);
    assert_eq!(tx_env.access_list, expected.access_list);
}

#[test]
fn prepare_call_block_env() {
    let block = Block {
        header: Default::default(),
        l1_fee_rate: Default::default(),
        l1_hash: Default::default(),
        transactions: Default::default(),
    };

    let sealed_block = &block.clone().seal();

    let block_env = BlockEnv::from(sealed_block);

    assert_eq!(block_env.number, block.header.number);
    assert_eq!(block_env.coinbase, block.header.beneficiary);
    assert_eq!(block_env.timestamp, block.header.timestamp);
    assert_eq!(
        block_env.basefee,
        block.header.base_fee_per_gas.unwrap_or_default()
    );
    assert_eq!(block_env.gas_limit, block.header.gas_limit);
    assert_eq!(block_env.prevrandao, block.header.mix_hash);
}
