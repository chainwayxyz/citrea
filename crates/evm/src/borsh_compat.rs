use alloy_consensus::{TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxLegacy};
use alloy_eips::eip7702::{Authorization, SignedAuthorization};
use alloy_primitives::{Parity, Signature, TxKind, U256};
use alloy_rpc_types::{AccessList, AccessListItem};
use borsh::{BorshDeserialize, BorshSerialize};
use bytes::Bytes;
use reth_primitives::{Transaction, TransactionSigned};

#[derive(BorshDeserialize, BorshSerialize)]
enum CompatParity {
    Eip155(u64),
    NonEip155(bool),
    Parity(bool),
}

impl From<Parity> for CompatParity {
    fn from(value: Parity) -> Self {
        match value {
            Parity::Eip155(x) => Self::Eip155(x),
            Parity::NonEip155(x) => Self::NonEip155(x),
            Parity::Parity(x) => Self::Parity(x),
        }
    }
}

impl From<CompatParity> for Parity {
    fn from(value: CompatParity) -> Self {
        match value {
            CompatParity::Eip155(x) => Self::Eip155(x),
            CompatParity::NonEip155(x) => Self::NonEip155(x),
            CompatParity::Parity(x) => Self::Parity(x),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
#[repr(transparent)]
struct CompatU256 {
    limbs: [u64; 4],
}

impl From<U256> for CompatU256 {
    fn from(value: U256) -> Self {
        Self {
            limbs: value.into_limbs(),
        }
    }
}

impl From<CompatU256> for U256 {
    fn from(value: CompatU256) -> Self {
        Self::from_limbs(value.limbs)
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct CompatSignature {
    v: CompatParity,
    r: CompatU256,
    s: CompatU256,
}

impl From<Signature> for CompatSignature {
    fn from(value: Signature) -> Self {
        Self {
            v: value.v().into(),
            r: value.r().into(),
            s: value.s().into(),
        }
    }
}

impl From<CompatSignature> for Signature {
    fn from(value: CompatSignature) -> Self {
        Self::new(value.r.into(), value.s.into(), value.v.into())
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
enum CompatTxKind {
    Create,
    Call([u8; 20]),
}

impl From<TxKind> for CompatTxKind {
    fn from(value: TxKind) -> Self {
        match value {
            TxKind::Create => Self::Create,
            TxKind::Call(x) => Self::Call(x.into()),
        }
    }
}

impl From<CompatTxKind> for TxKind {
    fn from(value: CompatTxKind) -> Self {
        match value {
            CompatTxKind::Create => Self::Create,
            CompatTxKind::Call(x) => Self::Call(x.into()),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct CompatAccessListItem {
    address: [u8; 20],
    storage_keys: Vec<[u8; 32]>,
}

impl From<AccessListItem> for CompatAccessListItem {
    fn from(value: AccessListItem) -> Self {
        Self {
            address: value.address.into(),
            storage_keys: value.storage_keys.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<CompatAccessListItem> for AccessListItem {
    fn from(value: CompatAccessListItem) -> Self {
        Self {
            address: value.address.into(),
            storage_keys: value.storage_keys.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct CompatAccessList(Vec<CompatAccessListItem>);

impl From<AccessList> for CompatAccessList {
    fn from(value: AccessList) -> Self {
        Self(value.0.into_iter().map(Into::into).collect())
    }
}

impl From<CompatAccessList> for AccessList {
    fn from(value: CompatAccessList) -> Self {
        Self(value.0.into_iter().map(Into::into).collect())
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct CompatAuthorization {
    chain_id: CompatU256,
    address: [u8; 20],
    nonce: u64,
}

impl From<Authorization> for CompatAuthorization {
    fn from(value: Authorization) -> Self {
        Self {
            chain_id: value.chain_id.into(),
            address: value.address.into(),
            nonce: value.nonce,
        }
    }
}

impl From<CompatAuthorization> for Authorization {
    fn from(value: CompatAuthorization) -> Self {
        Self {
            chain_id: value.chain_id.into(),
            address: value.address.into(),
            nonce: value.nonce,
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct CompatSignedAuthorization {
    inner: CompatAuthorization,
    signature: CompatSignature,
}

impl From<SignedAuthorization> for CompatSignedAuthorization {
    fn from(value: SignedAuthorization) -> Self {
        let (auth, sig) = value.into_parts();
        Self {
            inner: auth.into(),
            signature: sig.into(),
        }
    }
}

impl From<CompatSignedAuthorization> for SignedAuthorization {
    fn from(value: CompatSignedAuthorization) -> Self {
        let auth: Authorization = value.inner.into();
        auth.into_signed(value.signature.into())
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct CompatTxLegacy {
    chain_id: Option<u64>,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: CompatTxKind,
    value: CompatU256,
    input: Bytes,
}

impl From<TxLegacy> for CompatTxLegacy {
    fn from(value: TxLegacy) -> Self {
        Self {
            chain_id: value.chain_id,
            nonce: value.nonce,
            gas_price: value.gas_price,
            gas_limit: value.gas_limit,
            to: value.to.into(),
            value: value.value.into(),
            input: value.input.into(),
        }
    }
}

impl From<CompatTxLegacy> for TxLegacy {
    fn from(value: CompatTxLegacy) -> Self {
        Self {
            chain_id: value.chain_id,
            nonce: value.nonce,
            gas_price: value.gas_price,
            gas_limit: value.gas_limit,
            to: value.to.into(),
            value: value.value.into(),
            input: value.input.into(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct CompatTxEip2930 {
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: CompatTxKind,
    value: CompatU256,
    access_list: CompatAccessList,
    input: Bytes,
}

impl From<TxEip2930> for CompatTxEip2930 {
    fn from(value: TxEip2930) -> Self {
        Self {
            chain_id: value.chain_id,
            nonce: value.nonce,
            gas_price: value.gas_price,
            gas_limit: value.gas_limit,
            to: value.to.into(),
            value: value.value.into(),
            access_list: value.access_list.into(),
            input: value.input.into(),
        }
    }
}

impl From<CompatTxEip2930> for TxEip2930 {
    fn from(value: CompatTxEip2930) -> Self {
        Self {
            chain_id: value.chain_id,
            nonce: value.nonce,
            gas_price: value.gas_price,
            gas_limit: value.gas_limit,
            to: value.to.into(),
            value: value.value.into(),
            access_list: value.access_list.into(),
            input: value.input.into(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct CompatTxEip1559 {
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    to: CompatTxKind,
    value: CompatU256,
    access_list: CompatAccessList,
    input: Bytes,
}

impl From<TxEip1559> for CompatTxEip1559 {
    fn from(value: TxEip1559) -> Self {
        Self {
            chain_id: value.chain_id,
            nonce: value.nonce,
            gas_limit: value.gas_limit,
            max_fee_per_gas: value.max_fee_per_gas,
            max_priority_fee_per_gas: value.max_priority_fee_per_gas,
            to: value.to.into(),
            value: value.value.into(),
            access_list: value.access_list.into(),
            input: value.input.into(),
        }
    }
}

impl From<CompatTxEip1559> for TxEip1559 {
    fn from(value: CompatTxEip1559) -> Self {
        Self {
            chain_id: value.chain_id,
            nonce: value.nonce,
            gas_limit: value.gas_limit,
            max_fee_per_gas: value.max_fee_per_gas,
            max_priority_fee_per_gas: value.max_priority_fee_per_gas,
            to: value.to.into(),
            value: value.value.into(),
            access_list: value.access_list.into(),
            input: value.input.into(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct CompatTxEip4844 {
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    to: [u8; 20],
    value: CompatU256,
    access_list: CompatAccessList,
    blob_versioned_hashes: Vec<[u8; 32]>,
    max_fee_per_blob_gas: u128,
    input: Bytes,
}

impl From<TxEip4844> for CompatTxEip4844 {
    fn from(value: TxEip4844) -> Self {
        Self {
            chain_id: value.chain_id,
            nonce: value.nonce,
            gas_limit: value.gas_limit,
            max_fee_per_gas: value.max_fee_per_gas,
            max_priority_fee_per_gas: value.max_priority_fee_per_gas,
            to: value.to.into(),
            value: value.value.into(),
            access_list: value.access_list.into(),
            blob_versioned_hashes: value
                .blob_versioned_hashes
                .into_iter()
                .map(Into::into)
                .collect(),
            max_fee_per_blob_gas: value.max_fee_per_blob_gas,
            input: value.input.into(),
        }
    }
}

impl From<CompatTxEip4844> for TxEip4844 {
    fn from(value: CompatTxEip4844) -> Self {
        Self {
            chain_id: value.chain_id,
            nonce: value.nonce,
            gas_limit: value.gas_limit,
            max_fee_per_gas: value.max_fee_per_gas,
            max_priority_fee_per_gas: value.max_priority_fee_per_gas,
            to: value.to.into(),
            value: value.value.into(),
            access_list: value.access_list.into(),
            blob_versioned_hashes: value
                .blob_versioned_hashes
                .into_iter()
                .map(Into::into)
                .collect(),
            max_fee_per_blob_gas: value.max_fee_per_blob_gas,
            input: value.input.into(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct CompatTxEip7702 {
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    to: [u8; 20],
    value: CompatU256,
    access_list: CompatAccessList,
    authorization_list: Vec<CompatSignedAuthorization>,
    input: Bytes,
}

impl From<TxEip7702> for CompatTxEip7702 {
    fn from(value: TxEip7702) -> Self {
        Self {
            chain_id: value.chain_id,
            nonce: value.nonce,
            gas_limit: value.gas_limit,
            max_fee_per_gas: value.max_fee_per_gas,
            max_priority_fee_per_gas: value.max_priority_fee_per_gas,
            to: value.to.into(),
            value: value.value.into(),
            access_list: value.access_list.into(),
            authorization_list: value
                .authorization_list
                .into_iter()
                .map(Into::into)
                .collect(),
            input: value.input.into(),
        }
    }
}

impl From<CompatTxEip7702> for TxEip7702 {
    fn from(value: CompatTxEip7702) -> Self {
        Self {
            chain_id: value.chain_id,
            nonce: value.nonce,
            gas_limit: value.gas_limit,
            max_fee_per_gas: value.max_fee_per_gas,
            max_priority_fee_per_gas: value.max_priority_fee_per_gas,
            to: value.to.into(),
            value: value.value.into(),
            access_list: value.access_list.into(),
            authorization_list: value
                .authorization_list
                .into_iter()
                .map(Into::into)
                .collect(),
            input: value.input.into(),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
enum CompatTransaction {
    Legacy(CompatTxLegacy),
    Eip2930(CompatTxEip2930),
    Eip1559(CompatTxEip1559),
    Eip4844(CompatTxEip4844),
    Eip7702(CompatTxEip7702),
}

impl From<Transaction> for CompatTransaction {
    fn from(value: Transaction) -> Self {
        match value {
            Transaction::Legacy(x) => Self::Legacy(x.into()),
            Transaction::Eip2930(x) => Self::Eip2930(x.into()),
            Transaction::Eip1559(x) => Self::Eip1559(x.into()),
            Transaction::Eip4844(x) => Self::Eip4844(x.into()),
            Transaction::Eip7702(x) => Self::Eip7702(x.into()),
        }
    }
}

impl From<CompatTransaction> for Transaction {
    fn from(value: CompatTransaction) -> Self {
        match value {
            CompatTransaction::Legacy(x) => Self::Legacy(x.into()),
            CompatTransaction::Eip2930(x) => Self::Eip2930(x.into()),
            CompatTransaction::Eip1559(x) => Self::Eip1559(x.into()),
            CompatTransaction::Eip4844(x) => Self::Eip4844(x.into()),
            CompatTransaction::Eip7702(x) => Self::Eip7702(x.into()),
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
struct CompatTransactionSigned {
    pub hash: [u8; 32],
    pub signature: CompatSignature,
    pub transaction: CompatTransaction,
}

impl From<TransactionSigned> for CompatTransactionSigned {
    fn from(value: TransactionSigned) -> Self {
        Self {
            hash: value.hash.into(),
            signature: value.signature.into(),
            transaction: value.transaction.into(),
        }
    }
}

impl From<CompatTransactionSigned> for TransactionSigned {
    fn from(value: CompatTransactionSigned) -> Self {
        Self {
            hash: value.hash.into(),
            signature: value.signature.into(),
            transaction: value.transaction.into(),
        }
    }
}

fn compat_to_orig(txs: Vec<CompatTransactionSigned>) -> Vec<TransactionSigned> {
    fn assert_type<A, B>() {
        debug_assert_eq!(size_of::<A>(), size_of::<B>());
        debug_assert_eq!(align_of::<A>(), align_of::<B>());
    }
    assert_type::<TransactionSigned, CompatTransactionSigned>();
    assert_type::<TxLegacy, CompatTxLegacy>();
    assert_type::<TxEip2930, CompatTxEip2930>();
    assert_type::<TxEip1559, CompatTxEip1559>();
    assert_type::<TxEip4844, CompatTxEip4844>();
    assert_type::<TxEip7702, CompatTxEip7702>();
    assert_type::<Signature, CompatSignature>();
    assert_type::<SignedAuthorization, CompatSignedAuthorization>();
    assert_type::<Parity, CompatParity>();
    assert_type::<AccessList, CompatAccessList>();
    assert_type::<AccessListItem, CompatAccessListItem>();
    assert_type::<TxKind, CompatTxKind>();

    // Unfortunately `xs.into_iter().map(Into::into).collect()` is not
    //  optimized due to rustc limitations.

    unsafe { core::mem::transmute(txs) }
}

pub(crate) fn borsh_ser_txsigned<W: borsh::io::Write>(
    txs: &[TransactionSigned],
    writer: &mut W,
) -> Result<(), borsh::io::Error> {
    let txs: Vec<CompatTransactionSigned> = txs.iter().cloned().map(Into::into).collect();
    borsh::BorshSerialize::serialize(&txs, writer)
}

pub(crate) fn borsh_de_txsigned<R: borsh::io::Read>(
    reader: &mut R,
) -> Result<Vec<TransactionSigned>, borsh::io::Error> {
    let txs: Vec<CompatTransactionSigned> = borsh::BorshDeserialize::deserialize_reader(reader)?;
    let txs = compat_to_orig(txs);
    Ok(txs)
}
