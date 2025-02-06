use borsh::BorshDeserialize;
#[cfg(feature = "native")]
use sov_modules_core::PrivateKey;
use sov_modules_core::{Context, Signature};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::TransactionDigest;

#[cfg(feature = "native")]
use crate::default_signature::k256_private_key::K256PrivateKey;
#[cfg(feature = "native")]
use crate::default_signature::private_key::DefaultPrivateKey;
use crate::default_signature::{DefaultPublicKey, DefaultSignature, K256PublicKey, K256Signature};

const EXTEND_MESSAGE_LEN: usize = 2 * core::mem::size_of::<u64>();

/// A Transaction object that is compatible with the module-system/sov-default-stf.
#[derive(
    Debug, PartialEq, Eq, Clone, borsh::BorshDeserialize, borsh::BorshSerialize, serde::Serialize,
)]
pub struct Transaction {
    signature: Vec<u8>,
    pub_key: Vec<u8>,
    runtime_msg: Vec<u8>,
    chain_id: u64,
    nonce: u64,
}

/// A Transaction object that is compatible with the module-system/sov-default-stf.
#[derive(
    Debug, PartialEq, Eq, Clone, borsh::BorshDeserialize, borsh::BorshSerialize, serde::Serialize,
)]
pub struct PreFork2Transaction<C: Context> {
    signature: C::Signature,
    pub_key: C::PublicKey,
    runtime_msg: Vec<u8>,
    chain_id: u64,
    nonce: u64,
}

#[cfg(feature = "native")]
impl<C: Context> PreFork2Transaction<C> {
    pub fn new_signed_tx(priv_key: &[u8], mut message: Vec<u8>, chain_id: u64, nonce: u64) -> Self {
        // Since we own the message already, try to add the serialized nonce in-place.
        // This lets us avoid a copy if the message vec has at least 8 bytes of extra capacity.
        let len = message.len();

        // resizes once to avoid potential multiple realloc
        message.resize(len + EXTEND_MESSAGE_LEN, 0);

        message[len..len + 8].copy_from_slice(&chain_id.to_le_bytes());
        message[len + 8..len + 16].copy_from_slice(&nonce.to_le_bytes());

        // For other forks we should be using the ed25519 signatures
        let priv_key = C::PrivateKey::try_from(priv_key).unwrap();
        let pub_key = priv_key.pub_key();
        let signature = priv_key.sign(&message);

        // Don't forget to truncate the message back to its original length!
        message.truncate(len);

        Self {
            signature,
            runtime_msg: message,
            pub_key,
            chain_id,
            nonce,
        }
    }
}

impl<C: Context> From<PreFork2Transaction<C>> for Transaction {
    fn from(value: PreFork2Transaction<C>) -> Self {
        let signature = borsh::to_vec(&value.signature).unwrap();
        let pub_key = borsh::to_vec(&value.pub_key).unwrap();
        Self {
            signature,
            pub_key,
            runtime_msg: value.runtime_msg,
            chain_id: value.chain_id,
            nonce: value.nonce,
        }
    }
}

impl<C: Context> From<Transaction> for PreFork2Transaction<C> {
    fn from(value: Transaction) -> Self {
        let signature = C::Signature::try_from_slice(&value.signature).unwrap();
        let pub_key = C::PublicKey::try_from(value.pub_key.as_slice()).unwrap();
        Self {
            signature,
            pub_key,
            runtime_msg: value.runtime_msg,
            chain_id: value.chain_id,
            nonce: value.nonce,
        }
    }
}

impl Transaction {
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    pub fn runtime_msg(&self) -> &[u8] {
        &self.runtime_msg
    }

    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    pub const fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Check whether the transaction has been signed correctly.
    pub fn verify(&self, spec_id: SpecId) -> anyhow::Result<()> {
        if spec_id >= SpecId::Fork2 {
            // If we are at fork2 we should be using k256 signatures to verify sov txs
            let signature = K256Signature::try_from_slice(&self.signature)?;
            let pub_key = K256PublicKey::try_from(self.pub_key.as_slice())?;
            let mut serialized_tx =
                Vec::with_capacity(self.runtime_msg().len() + EXTEND_MESSAGE_LEN);

            serialized_tx.extend_from_slice(self.runtime_msg());
            serialized_tx.extend_from_slice(&self.chain_id().to_le_bytes());
            serialized_tx.extend_from_slice(&self.nonce().to_le_bytes());

            signature.verify(&pub_key, &serialized_tx)?;
        } else {
            // For other forks we should be using the ed25519 signatures
            let signature = DefaultSignature::try_from_slice(&self.signature)?;
            let pub_key = DefaultPublicKey::try_from(self.pub_key.as_slice())?;

            let mut serialized_tx =
                Vec::with_capacity(self.runtime_msg().len() + EXTEND_MESSAGE_LEN);

            serialized_tx.extend_from_slice(self.runtime_msg());
            serialized_tx.extend_from_slice(&self.chain_id().to_le_bytes());
            serialized_tx.extend_from_slice(&self.nonce().to_le_bytes());

            signature.verify(&pub_key, &serialized_tx)?;
        }

        Ok(())
    }
}

impl TransactionDigest for Transaction {
    fn compute_digest<D: digest::Digest>(&self) -> digest::Output<D> {
        let mut hasher = D::new();
        hasher.update(self.runtime_msg());
        hasher.update(self.chain_id().to_be_bytes());
        hasher.update(self.nonce().to_be_bytes());
        hasher.finalize()
    }
}

#[cfg(feature = "native")]
impl Transaction {
    /// New signed transaction.
    pub fn new_signed_tx(
        priv_key: &[u8],
        mut message: Vec<u8>,
        chain_id: u64,
        nonce: u64,
        spec_id: SpecId,
    ) -> Self {
        // Since we own the message already, try to add the serialized nonce in-place.
        // This lets us avoid a copy if the message vec has at least 8 bytes of extra capacity.
        let len = message.len();

        // resizes once to avoid potential multiple realloc
        message.resize(len + EXTEND_MESSAGE_LEN, 0);

        message[len..len + 8].copy_from_slice(&chain_id.to_le_bytes());
        message[len + 8..len + 16].copy_from_slice(&nonce.to_le_bytes());

        if spec_id >= SpecId::Fork2 {
            // If we are at fork2 we should be using k256 signatures to sign sov txs
            let priv_key = K256PrivateKey::try_from(priv_key).unwrap();
            let pub_key = priv_key.pub_key();
            let signature = priv_key.sign(&message);

            // Don't forget to truncate the message back to its original length!
            message.truncate(len);

            Self {
                signature: borsh::to_vec(&signature).unwrap(),
                runtime_msg: message,
                pub_key: borsh::to_vec(&pub_key).unwrap(),
                chain_id,
                nonce,
            }
        } else {
            // For other forks we should be using the ed25519 signatures
            let priv_key = DefaultPrivateKey::try_from(priv_key).unwrap();
            let pub_key = priv_key.pub_key();
            let signature = priv_key.sign(&message);

            // Don't forget to truncate the message back to its original length!
            message.truncate(len);

            Self {
                signature: borsh::to_vec(&signature).unwrap(),
                runtime_msg: message,
                pub_key: borsh::to_vec(&pub_key).unwrap(),
                chain_id,
                nonce,
            }
        }
    }
}
