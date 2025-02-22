use std::io::Read;

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "native")]
use sov_modules_core::PrivateKey;
use sov_modules_core::Signature;
use sov_rollup_interface::stf::TransactionDigest;

#[cfg(feature = "native")]
use crate::default_signature::k256_private_key::K256PrivateKey;
#[cfg(feature = "native")]
use crate::default_signature::private_key::DefaultPrivateKey;
use crate::default_signature::{DefaultPublicKey, DefaultSignature, K256PublicKey, K256Signature};

const EXTEND_MESSAGE_LEN: usize = 2 * core::mem::size_of::<u64>();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TxVersion {
    V1 = 0,
    V2 = 1,
}

/// A Transaction object that is compatible with the module-system/sov-default-stf.
#[derive(Debug, PartialEq, Eq, Clone, borsh::BorshDeserialize, borsh::BorshSerialize)]
pub struct TransactionV2 {
    signature: Vec<u8>,
    pub_key: Vec<u8>,
    runtime_msg: Vec<u8>,
    chain_id: u64,
    nonce: u64,
}

/// A Transaction object that is compatible with the module-system/sov-default-stf.
#[derive(Debug, PartialEq, Eq, Clone, borsh::BorshSerialize)]
pub struct TransactionV1 {
    signature: DefaultSignature,
    #[borsh(skip)]
    serialized_signature: Vec<u8>,
    pub_key: DefaultPublicKey,
    #[borsh(skip)]
    serialized_pub_key: Vec<u8>,
    runtime_msg: Vec<u8>,
    chain_id: u64,
    nonce: u64,
}

impl BorshDeserialize for TransactionV1 {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let signature = DefaultSignature::deserialize_reader(reader)?;
        let pub_key = DefaultPublicKey::deserialize_reader(reader)?;
        let runtime_msg = Vec::<u8>::deserialize_reader(reader)?;
        let chain_id = u64::deserialize_reader(reader)?;
        let nonce = u64::deserialize_reader(reader)?;

        Ok(Self {
            serialized_signature: borsh::to_vec(&signature)?,
            signature,
            serialized_pub_key: borsh::to_vec(&pub_key)?,
            pub_key,
            runtime_msg,
            chain_id,
            nonce,
        })
    }
}

/// The versioned transaction type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transaction {
    /// Pre Fork 2 version using ed25519 signatures
    V1(Box<TransactionV1>),
    /// Fork 2 version using k256 signatures
    V2(TransactionV2),
}

const V2_MAGIC_NUMBER: [u8; 4] = [0x54, 0x78, 0x56, 0x32]; // "TxV2"

impl BorshSerialize for Transaction {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        match self {
            Transaction::V2(tx) => {
                BorshSerialize::serialize(&V2_MAGIC_NUMBER, writer)?;
                BorshSerialize::serialize(tx, writer)
            }
            Transaction::V1(tx) => BorshSerialize::serialize(tx, writer),
        }
    }
}

impl BorshDeserialize for Transaction {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut peek_buf = [0u8; 4];

        match reader.read(&mut peek_buf) {
            Ok(4) if peek_buf == V2_MAGIC_NUMBER => {
                TransactionV2::deserialize_reader(reader).map(Transaction::V2)
            }
            Ok(n) => {
                let peek_cursor = std::io::Cursor::new(&peek_buf[..n]);
                let mut chained_reader = peek_cursor.chain(reader);
                TransactionV1::deserialize_reader(&mut chained_reader)
                    .map(|tx| Transaction::V1(Box::new(tx)))
            }
            Err(e) => Err(e),
        }
    }
}

impl Transaction {
    pub fn version(&self) -> TxVersion {
        match self {
            Self::V2 { .. } => TxVersion::V2,
            Self::V1 { .. } => TxVersion::V1,
        }
    }

    pub fn signature(&self) -> &[u8] {
        match self {
            Self::V1(tx) => tx.serialized_signature.as_slice(),
            Self::V2(tx) => tx.signature.as_slice(),
        }
    }

    pub fn pub_key(&self) -> &[u8] {
        match self {
            Self::V1(tx) => tx.serialized_pub_key.as_slice(),
            Self::V2(tx) => tx.pub_key.as_slice(),
        }
    }

    pub fn runtime_msg(&self) -> &[u8] {
        match self {
            Self::V2(tx) => &tx.runtime_msg,
            Self::V1(tx) => &tx.runtime_msg,
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            Self::V2(tx) => tx.nonce,
            Self::V1(tx) => tx.nonce,
        }
    }

    pub fn chain_id(&self) -> u64 {
        match self {
            Self::V2(tx) => tx.chain_id,
            Self::V1(tx) => tx.chain_id,
        }
    }

    pub fn to_blob(&self) -> Result<Vec<u8>, borsh::io::Error> {
        borsh::to_vec(self)
    }

    #[cfg(feature = "native")]
    pub fn new_signed_tx(
        priv_key: &[u8],
        runtime_msg: Vec<u8>,
        chain_id: u64,
        nonce: u64,
        fork2: bool,
    ) -> Self {
        let mut message = Vec::with_capacity(runtime_msg.len() + EXTEND_MESSAGE_LEN);
        message.extend_from_slice(&runtime_msg);
        message.extend_from_slice(&chain_id.to_le_bytes());
        message.extend_from_slice(&nonce.to_le_bytes());

        if fork2 {
            let priv_key = K256PrivateKey::try_from(priv_key).unwrap();
            let pub_key = priv_key.pub_key();
            let signature = priv_key.sign(&message);

            Self::V2(TransactionV2 {
                signature: borsh::to_vec(&signature).unwrap(),
                pub_key: borsh::to_vec(&pub_key).unwrap(),
                runtime_msg,
                chain_id,
                nonce,
            })
        } else {
            let priv_key = DefaultPrivateKey::try_from(priv_key).unwrap();
            let pub_key = priv_key.pub_key();
            let signature = priv_key.sign(&message);

            Self::V1(Box::new(TransactionV1 {
                serialized_signature: borsh::to_vec(&signature).unwrap(),
                signature,
                serialized_pub_key: borsh::to_vec(&pub_key).unwrap(),
                pub_key,
                runtime_msg,
                chain_id,
                nonce,
            }))
        }
    }

    pub fn verify(&self) -> anyhow::Result<()> {
        match self {
            Self::V1(tx) => {
                let mut serialized_tx =
                    Vec::with_capacity(tx.runtime_msg.len() + EXTEND_MESSAGE_LEN);

                serialized_tx.extend_from_slice(&tx.runtime_msg);
                serialized_tx.extend_from_slice(&tx.chain_id.to_le_bytes());
                serialized_tx.extend_from_slice(&tx.nonce.to_le_bytes());

                tx.signature.verify(&tx.pub_key, &serialized_tx)?;
            }
            Self::V2(tx) => {
                let signature = K256Signature::try_from_slice(&tx.signature)?;
                let pub_key = K256PublicKey::try_from(tx.pub_key.as_slice())?;
                let mut serialized_tx =
                    Vec::with_capacity(tx.runtime_msg.len() + EXTEND_MESSAGE_LEN);

                serialized_tx.extend_from_slice(&tx.runtime_msg);
                serialized_tx.extend_from_slice(&tx.chain_id.to_le_bytes());
                serialized_tx.extend_from_slice(&tx.nonce.to_le_bytes());

                signature.verify(&pub_key, &serialized_tx)?;
            }
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
