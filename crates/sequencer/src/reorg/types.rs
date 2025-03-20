use std::hash::Hash;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use digest::Digest;
use ed25519_dalek::{
    Signature as DalekSignature, SigningKey, VerifyingKey as DalekPublicKey, KEYPAIR_LENGTH,
    PUBLIC_KEY_LENGTH,
};
use serde::{Deserialize, Serialize};
use sov_keys::default_signature::SigVerificationError;
use sov_keys::{PublicKey, PublicKeyHex, Signature};
use sov_modules_api::{Address, Context, Spec, SpecId};
use sov_modules_core::{StateKeyCodec, StateValueCodec};
use sov_rollup_interface::rpc::HexTx;
use sov_state::codec::BorshCodec;
use sov_state::ProverStorage;

/// The response to a JSON-RPC request for a particular soft confirmation.
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SoftConfirmationResponse {
    /// The L2 height of the soft confirmation.
    pub l2_height: u64,
    /// The DA height of the soft confirmation.
    pub da_slot_height: u64,
    /// The DA slothash of the soft confirmation.
    // TODO: find a way to hex serialize this and then
    // deserialize in `SequencerClient`
    #[serde(with = "hex::serde")]
    pub da_slot_hash: [u8; 32],
    #[serde(with = "hex::serde")]
    /// The DA slot transactions commitment of the soft confirmation.
    pub da_slot_txs_commitment: [u8; 32],
    /// The hash of the soft confirmation.
    #[serde(with = "hex::serde")]
    pub hash: [u8; 32],
    /// The hash of the previous soft confirmation.
    #[serde(with = "hex::serde")]
    pub prev_hash: [u8; 32],
    /// The transactions in this batch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub txs: Option<Vec<HexTx>>,
    /// State root of the soft confirmation.
    #[serde(with = "hex::serde")]
    pub state_root: [u8; 32],
    /// Signature of the batch
    #[serde(with = "hex::serde")]
    pub soft_confirmation_signature: Vec<u8>,
    /// Public key of the signer
    #[serde(with = "hex::serde")]
    pub pub_key: Vec<u8>,
    /// Deposit data from the L1 chain
    pub deposit_data: Vec<HexTx>, // Vec<u8> wrapper around deposit data
    /// Base layer fee rate sats/wei etc. per byte.
    pub l1_fee_rate: u128,
    /// Sequencer's block timestamp.
    pub timestamp: u64,
    /// Tx merkle root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_merkle_root: Option<[u8; 32]>,
}

/// A Transaction object that is compatible with the module-system/sov-default-stf.
#[derive(
    Debug, PartialEq, Eq, Clone, borsh::BorshDeserialize, borsh::BorshSerialize, serde::Serialize,
)]
pub struct PreFork2Transaction<C: sov_modules_api::Context> {
    pub signature: C::Signature,
    pub pub_key: C::PublicKey,
    pub runtime_msg: Vec<u8>,
    pub chain_id: u64,
    pub nonce: u64,
}

#[derive(Clone, Debug, PartialEq, BorshDeserialize, BorshSerialize, Serialize, Deserialize)]
pub struct PreFork2Context {
    pub sender: Address,
    pub l1_fee_rate: u128,
    pub active_spec: SpecId,
    /// The height to report. This is set by the kernel when the context is created
    visible_height: u64,
}

impl Spec for PreFork2Context {
    type Address = Address;
    type Storage = ProverStorage;
    type PrivateKey = private_key::DefaultPrivateKey;
    type PublicKey = DefaultPublicKey;
    type Hasher = sha2::Sha256;
    type Signature = DefaultSignature;
}

impl Context for PreFork2Context {
    fn sender(&self) -> &Self::Address {
        &self.sender
    }

    fn new(sender: Self::Address, height: u64, active_spec: SpecId, l1_fee_rate: u128) -> Self {
        Self {
            sender,
            l1_fee_rate,
            active_spec,
            visible_height: height,
        }
    }

    fn slot_height(&self) -> u64 {
        self.visible_height
    }

    fn active_spec(&self) -> SpecId {
        self.active_spec
    }

    fn l1_fee_rate(&self) -> u128 {
        self.l1_fee_rate
    }
}

pub mod private_key {
    use ed25519_dalek::{Signer, SigningKey, KEYPAIR_LENGTH, SECRET_KEY_LENGTH};
    use sov_keys::PrivateKey;
    use thiserror::Error;

    use super::{DefaultPublicKey, DefaultSignature};

    #[derive(Error, Debug)]
    pub enum DefaultPrivateKeyDeserializationError {
        #[error("Hex deserialization error")]
        FromHexError(#[from] hex::FromHexError),
        #[error("KeyPairError deserialization error")]
        KeyPairError(#[from] ed25519_dalek::SignatureError),
        #[error("Invalid private key length: {actual}, expected {expected_1} or {expected_2}")]
        InvalidPrivateKeyLength {
            expected_1: usize,
            expected_2: usize,
            actual: usize,
        },
    }

    /// A private key for the default signature scheme.
    /// This struct also stores the corresponding public key.
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    pub struct DefaultPrivateKey {
        pub key_pair: SigningKey,
    }

    impl DefaultPrivateKey {
        // This is private method and panics if input slice has incorrect length
        fn try_from_keypair(value: &[u8]) -> Result<Self, DefaultPrivateKeyDeserializationError> {
            let value: [u8; KEYPAIR_LENGTH] = value
                .try_into()
                .expect("incorrect usage of `try_from_keypair`, check input length");
            let key_pair = SigningKey::from_keypair_bytes(&value)?;
            Ok(Self { key_pair })
        }

        // This is private method and panics if input slice has incorrect length
        fn try_from_private_key(value: &[u8]) -> Self {
            let value: [u8; SECRET_KEY_LENGTH] = value
                .try_into()
                .expect("incorrect usage of `try_from_private_key`, check input length");
            let key_pair = SigningKey::from_bytes(&value);
            Self { key_pair }
        }
    }

    impl core::fmt::Debug for DefaultPrivateKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DefaultPrivateKey")
                .field("public_key", &self.key_pair.verifying_key())
                .field("private_key", &"***REDACTED***")
                .finish()
        }
    }

    impl TryFrom<&[u8]> for DefaultPrivateKey {
        type Error = anyhow::Error;

        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            if value.len() == KEYPAIR_LENGTH {
                Self::try_from_keypair(value).map_err(|e| e.into())
            } else if value.len() == SECRET_KEY_LENGTH {
                Ok(Self::try_from_private_key(value))
            } else {
                let err = Err(
                    DefaultPrivateKeyDeserializationError::InvalidPrivateKeyLength {
                        expected_1: SECRET_KEY_LENGTH,
                        expected_2: KEYPAIR_LENGTH,
                        actual: value.len(),
                    },
                );
                err.map_err(|e| e.into())
            }
        }
    }

    impl PrivateKey for DefaultPrivateKey {
        type PublicKey = DefaultPublicKey;

        type Signature = DefaultSignature;

        fn pub_key(&self) -> Self::PublicKey {
            DefaultPublicKey {
                pub_key: self.key_pair.verifying_key(),
            }
        }

        fn sign(&self, msg: &[u8]) -> Self::Signature {
            DefaultSignature {
                msg_sig: self.key_pair.sign(msg),
            }
        }

        fn generate() -> Self {
            todo!()
        }
    }
}

#[derive(
    PartialEq, Eq, Clone, Debug, schemars::JsonSchema, serde::Serialize, serde::Deserialize,
)]
pub struct DefaultPublicKey {
    #[schemars(with = "&[u8]", length(equal = "ed25519_dalek::PUBLIC_KEY_LENGTH"))]
    pub(crate) pub_key: DalekPublicKey,
}

impl Hash for DefaultPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pub_key.as_bytes().hash(state);
    }
}

impl BorshDeserialize for DefaultPublicKey {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buffer = [0; PUBLIC_KEY_LENGTH];
        reader.read_exact(&mut buffer)?;

        let pub_key = DalekPublicKey::from_bytes(&buffer).map_err(map_error)?;

        Ok(Self { pub_key })
    }
}

impl BorshSerialize for DefaultPublicKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(self.pub_key.as_bytes())
    }
}

impl StateKeyCodec<DefaultPublicKey> for BorshCodec {
    fn encode_key(&self, value: &DefaultPublicKey) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        BorshSerialize::serialize(value, &mut buf).unwrap();
        buf
    }
}

impl StateValueCodec<DefaultPublicKey> for BorshCodec {
    type Error = std::io::Error;

    fn encode_value(&self, value: &DefaultPublicKey) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        BorshSerialize::serialize(value, &mut buf).unwrap();
        buf
    }

    fn try_decode_value(&self, bytes: &[u8]) -> Result<DefaultPublicKey, Self::Error> {
        borsh::from_slice(bytes)
    }
}

impl TryFrom<&[u8]> for DefaultPublicKey {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() == KEYPAIR_LENGTH {
            let mut keypair = [0u8; KEYPAIR_LENGTH];
            keypair.copy_from_slice(value);
            let keypair = SigningKey::from_keypair_bytes(&keypair).map_err(anyhow::Error::msg)?;
            Ok(Self {
                pub_key: keypair.verifying_key(),
            })
        } else if value.len() == PUBLIC_KEY_LENGTH {
            let mut public = [0u8; PUBLIC_KEY_LENGTH];
            public.copy_from_slice(value);
            Ok(Self {
                pub_key: DalekPublicKey::from_bytes(&public).map_err(anyhow::Error::msg)?,
            })
        } else {
            anyhow::bail!("Unexpected public key length")
        }
    }
}

#[derive(
    PartialEq, Eq, Debug, Clone, schemars::JsonSchema, serde::Serialize, serde::Deserialize,
)]
pub struct DefaultSignature {
    #[schemars(with = "&[u8]", length(equal = "ed25519_dalek::Signature::BYTE_SIZE"))]
    pub msg_sig: DalekSignature,
}

impl BorshDeserialize for DefaultSignature {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buffer = [0; DalekSignature::BYTE_SIZE];
        reader.read_exact(&mut buffer)?;

        Ok(Self {
            msg_sig: DalekSignature::from_bytes(&buffer),
        })
    }
}

impl BorshSerialize for DefaultSignature {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.msg_sig.to_bytes())
    }
}

impl TryFrom<&[u8]> for DefaultSignature {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            msg_sig: DalekSignature::from_slice(value).map_err(anyhow::Error::msg)?,
        })
    }
}

impl Signature for DefaultSignature {
    type PublicKey = DefaultPublicKey;

    fn verify(&self, pub_key: &Self::PublicKey, msg: &[u8]) -> Result<(), SigVerificationError> {
        pub_key
            .pub_key
            .verify_strict(msg, &self.msg_sig)
            .map_err(|e| SigVerificationError::BadSignature(e.to_string()))
    }
}

fn map_error(_e: ed25519_dalek::SignatureError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, "Signature error")
}

impl FromStr for DefaultPublicKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pk_hex = &PublicKeyHex::try_from(s)?;
        pk_hex.try_into()
    }
}

impl FromStr for DefaultSignature {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;

        let bytes: ed25519_dalek::ed25519::SignatureBytes = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature"))?;

        Ok(DefaultSignature {
            msg_sig: DalekSignature::from_bytes(&bytes),
        })
    }
}

impl PublicKey for DefaultPublicKey {
    fn to_address<A: From<[u8; 32]>>(&self) -> A {
        let pub_key_hash = {
            let mut hasher = <PreFork2Context as Spec>::Hasher::new();
            hasher.update(self.pub_key);
            hasher.finalize().into()
        };
        A::from(pub_key_hash)
    }
}

impl From<&DefaultPublicKey> for PublicKeyHex {
    fn from(pub_key: &DefaultPublicKey) -> Self {
        let hex = hex::encode(pub_key.pub_key.as_bytes());
        Self::new(hex)
    }
}

impl TryFrom<&PublicKeyHex> for DefaultPublicKey {
    type Error = anyhow::Error;

    fn try_from(pub_key: &PublicKeyHex) -> Result<Self, Self::Error> {
        let bytes = hex::decode(pub_key.hex())?;

        let bytes: [u8; PUBLIC_KEY_LENGTH] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid public key size"))?;

        let pub_key = DalekPublicKey::from_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("Invalid public key"))?;

        Ok(DefaultPublicKey { pub_key })
    }
}
