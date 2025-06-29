#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "native")]
use sov_keys::default_signature::k256_private_key::K256PrivateKey;
use sov_keys::default_signature::{K256PublicKey, K256Signature};
#[cfg(feature = "native")]
use sov_keys::PrivateKey;
use sov_keys::Signature;

#[cfg(feature = "native")]
use crate::spec::SpecId;

const EXTEND_MESSAGE_LEN: usize = 1 + 2 * core::mem::size_of::<u64>(); // version (u8) + chain_id (u64) + nonce (u64)

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum TxVersion {
    V1 = 0,
    V2 = 1,
}

/// A Transaction object that is compatible with the module-system/sov-default-stf.
#[derive(Debug, PartialEq, Eq, Clone, borsh::BorshDeserialize, borsh::BorshSerialize)]
pub struct TransactionV1 {
    signature: Vec<u8>,
    pub_key: K256PublicKey,
    runtime_msg: Vec<u8>,
    chain_id: u64,
    nonce: u64,
}

impl TransactionV1 {
    #[cfg(feature = "native")]
    fn new(priv_key: &K256PrivateKey, runtime_msg: Vec<u8>, chain_id: u64, nonce: u64) -> Self {
        let mut message = Vec::with_capacity(runtime_msg.len() + EXTEND_MESSAGE_LEN);
        message.extend_from_slice(&runtime_msg);
        message.extend_from_slice(&chain_id.to_le_bytes());
        message.extend_from_slice(&nonce.to_le_bytes());

        let pub_key = priv_key.pub_key();
        let signature = priv_key.sign(&message);

        Self {
            signature: borsh::to_vec(&signature).unwrap(),
            pub_key,
            runtime_msg,
            chain_id,
            nonce,
        }
    }

    fn verify(&self) -> anyhow::Result<()> {
        let signature = K256Signature::try_from_slice(&self.signature)?;
        let mut serialized_tx = Vec::with_capacity(self.runtime_msg.len() + EXTEND_MESSAGE_LEN);

        serialized_tx.extend_from_slice(&self.runtime_msg);
        serialized_tx.extend_from_slice(&self.chain_id.to_le_bytes());
        serialized_tx.extend_from_slice(&self.nonce.to_le_bytes());

        signature.verify(&self.pub_key, &serialized_tx)?;
        Ok(())
    }

    pub fn compute_digest<D: digest::Digest>(&self) -> digest::Output<D> {
        let mut hasher = D::new();
        hasher.update(&self.runtime_msg);
        hasher.update(self.chain_id.to_be_bytes());
        hasher.update(self.nonce.to_be_bytes());
        hasher.finalize()
    }
}

/// A Transaction object that is compatible with the module-system/sov-default-stf.
#[derive(Debug, PartialEq, Eq, Clone, borsh::BorshDeserialize, borsh::BorshSerialize)]
pub struct TransactionV2 {
    signature: K256Signature,
    pub_key: K256PublicKey,
    runtime_msg: Vec<u8>,
    chain_id: u64,
    nonce: u64,
}

impl TransactionV2 {
    #[cfg(feature = "native")]
    fn new(priv_key: &K256PrivateKey, runtime_msg: Vec<u8>, chain_id: u64, nonce: u64) -> Self {
        let mut message = Vec::with_capacity(runtime_msg.len() + EXTEND_MESSAGE_LEN);
        message.extend([TxVersion::V2 as u8]);
        message.extend_from_slice(&runtime_msg);
        message.extend_from_slice(&chain_id.to_be_bytes());
        message.extend_from_slice(&nonce.to_be_bytes());

        let pub_key = priv_key.pub_key();
        let signature = priv_key.sign(&message);

        Self {
            signature,
            pub_key,
            runtime_msg,
            chain_id,
            nonce,
        }
    }

    fn verify(&self) -> anyhow::Result<()> {
        let mut serialized_tx = Vec::with_capacity(self.runtime_msg.len() + EXTEND_MESSAGE_LEN);

        serialized_tx.extend([TxVersion::V2 as u8]);
        serialized_tx.extend_from_slice(&self.runtime_msg);
        serialized_tx.extend_from_slice(&self.chain_id.to_be_bytes());
        serialized_tx.extend_from_slice(&self.nonce.to_be_bytes());

        self.signature.verify(&self.pub_key, &serialized_tx)?;
        Ok(())
    }

    pub fn compute_digest<D: digest::Digest>(&self) -> digest::Output<D> {
        let mut hasher = D::new();
        hasher.update([TxVersion::V2 as u8]);
        hasher.update(&self.runtime_msg);
        hasher.update(self.chain_id.to_be_bytes());
        hasher.update(self.nonce.to_be_bytes());
        hasher.finalize()
    }
}

/// The versioned transaction type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transaction {
    V1(TransactionV1),
    V2(TransactionV2),
}

impl BorshSerialize for Transaction {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.version(), writer)?;

        match self {
            Transaction::V1(tx) => BorshSerialize::serialize(tx, writer),
            Transaction::V2(tx) => BorshSerialize::serialize(tx, writer),
        }
    }
}

impl BorshDeserialize for Transaction {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let version = TxVersion::deserialize_reader(reader)?;

        match version {
            TxVersion::V1 => TransactionV1::deserialize_reader(reader).map(Transaction::V1),
            TxVersion::V2 => TransactionV2::deserialize_reader(reader).map(Transaction::V2),
        }
    }
}

impl Transaction {
    pub fn version(&self) -> TxVersion {
        match self {
            Self::V1 { .. } => TxVersion::V1,
            Self::V2 { .. } => TxVersion::V2,
        }
    }

    pub fn pub_key(&self) -> &K256PublicKey {
        match self {
            Self::V1(tx) => &tx.pub_key,
            Self::V2(tx) => &tx.pub_key,
        }
    }

    pub fn runtime_msg(&self) -> &[u8] {
        match self {
            Self::V1(tx) => &tx.runtime_msg,
            Self::V2(tx) => &tx.runtime_msg,
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            Self::V1(tx) => tx.nonce,
            Self::V2(tx) => tx.nonce,
        }
    }

    pub fn chain_id(&self) -> u64 {
        match self {
            Self::V1(tx) => tx.chain_id,
            Self::V2(tx) => tx.chain_id,
        }
    }

    pub fn to_blob(&self) -> Result<Vec<u8>, borsh::io::Error> {
        borsh::to_vec(self)
    }

    #[cfg(feature = "native")]
    pub fn new_signed_tx(
        spec: SpecId,
        priv_key: &K256PrivateKey,
        runtime_msg: Vec<u8>,
        chain_id: u64,
        nonce: u64,
    ) -> Self {
        if spec >= SpecId::Fork3 {
            Self::V2(TransactionV2::new(priv_key, runtime_msg, chain_id, nonce))
        } else {
            Self::V1(TransactionV1::new(priv_key, runtime_msg, chain_id, nonce))
        }
    }

    pub fn verify(&self) -> anyhow::Result<()> {
        match self {
            Self::V1(tx) => tx.verify(),
            Self::V2(tx) => tx.verify(),
        }
    }

    pub fn compute_digest<D: digest::Digest>(&self) -> digest::Output<D> {
        match self {
            Self::V1(tx) => tx.compute_digest::<D>(),
            Self::V2(tx) => tx.compute_digest::<D>(),
        }
    }
}
