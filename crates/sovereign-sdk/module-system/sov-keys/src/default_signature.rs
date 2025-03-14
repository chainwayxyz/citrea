use std::fmt::Debug;
use std::hash::Hash;
#[cfg(feature = "native")]
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{
    Signature as DalekSignature, SigningKey, VerifyingKey as DalekPublicKey, KEYPAIR_LENGTH,
    PUBLIC_KEY_LENGTH,
};
use sha2::Digest;

use crate::{PublicKey, Signature};

/// Representation of a signature verification error.
#[derive(Debug)]
#[cfg_attr(feature = "native", derive(thiserror::Error))]
pub enum SigVerificationError {
    /// The signature is invalid for the provided public key.
    #[cfg_attr(feature = "native", error("Bad signature {0}"))]
    BadSignature(String),
}

#[cfg(not(feature = "native"))]
impl core::fmt::Display for SigVerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        <SigVerificationError as core::fmt::Debug>::fmt(self, f)
    }
}

#[cfg(feature = "native")]
pub mod k256_private_key {
    use k256::ecdsa::signature::Signer;
    use k256::ecdsa::SigningKey;
    use rand::rngs::OsRng;

    use super::{K256PublicKey, K256Signature};
    use crate::PrivateKey;

    #[derive(Clone)]
    pub struct K256PrivateKey {
        pub key_pair: SigningKey,
    }

    // TODO: Should we implement try_from_keypair? We can set private_key_length, public_key_length and keypair_length as constants which are 32,33,65 respectively

    impl TryFrom<&[u8]> for K256PrivateKey {
        type Error = anyhow::Error;

        fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
            let key_pair = SigningKey::from_slice(value)?;
            Ok(Self { key_pair })
        }
    }

    impl core::fmt::Debug for K256PrivateKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("K256PrivateKey")
                .field("public_key", &self.key_pair.verifying_key())
                .field("private_key", &"***REDACTED***")
                .finish()
        }
    }

    impl PrivateKey for K256PrivateKey {
        type PublicKey = K256PublicKey;

        type Signature = K256Signature;

        fn generate() -> Self {
            let mut csprng = OsRng;

            Self {
                key_pair: SigningKey::random(&mut csprng),
            }
        }

        fn pub_key(&self) -> K256PublicKey {
            K256PublicKey {
                pub_key: *self.key_pair.verifying_key(),
            }
        }

        fn sign(&self, msg: &[u8]) -> Self::Signature {
            K256Signature {
                msg_sig: self.key_pair.sign(msg),
            }
        }
    }

    impl K256PrivateKey {
        pub fn as_hex(&self) -> String {
            hex::encode(self.key_pair.to_bytes())
        }

        pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
            let bytes = hex::decode(hex)?;
            Self::try_from(&bytes[..])
        }
    }
}

#[cfg(feature = "native")]
pub mod private_key {
    use ed25519_dalek::{Signer, SigningKey, KEYPAIR_LENGTH, SECRET_KEY_LENGTH};
    use rand::rngs::OsRng;
    use thiserror::Error;

    use super::{DefaultPublicKey, DefaultSignature};
    use crate::PrivateKey;

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

        fn generate() -> Self {
            let mut csprng = OsRng;

            Self {
                key_pair: SigningKey::generate(&mut csprng),
            }
        }

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
    }

    impl DefaultPrivateKey {
        pub fn as_hex(&self) -> String {
            hex::encode(self.key_pair.to_bytes())
        }

        pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
            let bytes = hex::decode(hex)?;
            Self::try_from(&bytes[..])
        }
    }
}

#[cfg_attr(feature = "native", derive(schemars::JsonSchema))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct K256PublicKey {
    #[cfg_attr(feature = "native", schemars(with = "&[u8]", length(equal = 33)))]
    pub pub_key: k256::ecdsa::VerifyingKey,
}

impl Hash for K256PublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.pub_key.to_sec1_bytes().hash(state);
    }
}

impl BorshDeserialize for K256PublicKey {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // k256 (compressed, 33 byte key length): secp256k1-pub, code 0xE7, varint bytes: [0xE7, 0x01]
        let mut buffer = [0; 33];
        reader.read_exact(&mut buffer)?;

        let pub_key =
            k256::ecdsa::VerifyingKey::from_sec1_bytes(&buffer).map_err(map_error_k256)?;

        Ok(Self { pub_key })
    }
}

impl BorshSerialize for K256PublicKey {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.pub_key.to_sec1_bytes())
    }
}

impl TryFrom<&[u8]> for K256PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut public = [0u8; 33];
        public.copy_from_slice(value);
        Ok(Self {
            pub_key: k256::ecdsa::VerifyingKey::from_sec1_bytes(&public)
                .map_err(anyhow::Error::msg)?,
        })
    }
}

#[cfg_attr(feature = "native", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct K256Signature {
    #[cfg_attr(feature = "native", schemars(with = "&[u8]", length(equal = 64)))]
    pub(crate) msg_sig: k256::ecdsa::Signature,
}

impl BorshDeserialize for K256Signature {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        // k256 (64 byte signature length): secp256k1-sig, code 0xE8, varint bytes: [0xE8, 0x01]
        let mut buffer = [0; 64];
        reader.read_exact(&mut buffer)?;

        let msg_sig = k256::ecdsa::Signature::from_slice(&buffer).map_err(map_error)?;

        Ok(Self { msg_sig })
    }
}

impl BorshSerialize for K256Signature {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.msg_sig.to_bytes())
    }
}

impl TryFrom<&[u8]> for K256Signature {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            msg_sig: k256::ecdsa::Signature::from_slice(value).map_err(anyhow::Error::msg)?,
        })
    }
}

impl Signature for K256Signature {
    type PublicKey = K256PublicKey;

    fn verify(&self, pub_key: &Self::PublicKey, msg: &[u8]) -> Result<(), SigVerificationError> {
        use k256::ecdsa::signature::Verifier;
        pub_key
            .pub_key
            .verify(msg, &self.msg_sig)
            .map_err(|e| SigVerificationError::BadSignature(e.to_string()))
    }
}

#[cfg_attr(feature = "native", derive(schemars::JsonSchema))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DefaultPublicKey {
    #[cfg_attr(
        feature = "native",
        schemars(with = "&[u8]", length(equal = "ed25519_dalek::PUBLIC_KEY_LENGTH"))
    )]
    pub pub_key: DalekPublicKey,
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

impl PublicKey for DefaultPublicKey {
    fn to_address<A: From<[u8; 32]>>(&self) -> A {
        let pub_key_hash = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(self.pub_key);
            hasher.finalize().into()
        };
        A::from(pub_key_hash)
    }
}

impl PublicKey for K256PublicKey {
    fn to_address<A: From<[u8; 32]>>(&self) -> A {
        let pub_key_hash = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(self.pub_key.to_sec1_bytes());
            hasher.finalize().into()
        };
        A::from(pub_key_hash)
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

#[cfg_attr(feature = "native", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct DefaultSignature {
    #[cfg_attr(
        feature = "native",
        schemars(with = "&[u8]", length(equal = "ed25519_dalek::Signature::BYTE_SIZE"))
    )]
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

#[cfg(feature = "native")]
fn map_error(e: ed25519_dalek::SignatureError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}
#[cfg(not(feature = "native"))]
fn map_error(_e: ed25519_dalek::SignatureError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, "Signature error")
}

#[cfg(feature = "native")]
fn map_error_k256(e: k256::ecdsa::signature::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}
#[cfg(not(feature = "native"))]
fn map_error_k256(_e: k256::ecdsa::signature::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, "Signature error")
}

#[cfg(feature = "native")]
impl FromStr for DefaultPublicKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pk_hex = &crate::pub_key_hex::PublicKeyHex::try_from(s)?;
        pk_hex.try_into()
    }
}

#[cfg(feature = "native")]
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

#[cfg(feature = "native")]
impl FromStr for K256PublicKey {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pk_hex = &crate::pub_key_hex::PublicKeyHex::try_from(s)?;
        pk_hex.try_into()
    }
}

#[cfg(feature = "native")]
impl FromStr for K256Signature {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;

        let bytes: [u8; 64] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature"))?;

        Ok(K256Signature {
            msg_sig: k256::ecdsa::Signature::from_slice(&bytes)
                .map_err(|_| anyhow::anyhow!("Invalid signature"))?,
        })
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use borsh::BorshDeserialize;

    use super::k256_private_key::K256PrivateKey;
    use crate::default_signature::private_key::DefaultPrivateKey;
    use crate::default_signature::{
        DefaultPublicKey, DefaultSignature, K256PublicKey, K256Signature,
    };
    use crate::{PrivateKey, Signature};

    #[test]
    #[cfg(feature = "native")]
    fn test_privatekey_serde_bincode() {
        let key_pair = DefaultPrivateKey::generate();
        let serialized = bincode::serialize(&key_pair).expect("Serialization to vec is infallible");
        let output = bincode::deserialize::<DefaultPrivateKey>(&serialized)
            .expect("SigningKey is serialized correctly");

        assert_eq!(key_pair.as_hex(), output.as_hex());
    }

    #[test]
    #[cfg(feature = "native")]
    fn test_privatekey_serde_json() {
        let key_pair = DefaultPrivateKey::generate();
        let serialized = serde_json::to_vec(&key_pair).expect("Serialization to vec is infallible");
        let output = serde_json::from_slice::<DefaultPrivateKey>(&serialized)
            .expect("Keypair is serialized correctly");

        assert_eq!(key_pair.as_hex(), output.as_hex());
    }

    #[test]
    fn test_k256_signature_operations() {
        let sequ_pk = K256PrivateKey::from_hex(
            "1212121212121212121212121212121212121212121212121212121212121212",
        )
        .unwrap();

        let sequ_pub_key = sequ_pk.pub_key();
        let sequ_pub_key_sec1 = sequ_pub_key.pub_key.to_sec1_bytes();
        println!("sequ_pub_key_sec1: {:?}", sequ_pub_key_sec1.to_vec());
        let sequ_pub_key_sec1_hex = hex::encode(sequ_pub_key_sec1.clone());

        let sequ_pub_key = K256PublicKey::try_from(sequ_pub_key_sec1.to_vec().as_slice()).unwrap();

        let sequ_pub_key_from_hex = K256PublicKey::from_str(&sequ_pub_key_sec1_hex).unwrap();

        assert_eq!(sequ_pub_key, sequ_pk.pub_key());
        assert_eq!(sequ_pub_key_from_hex, sequ_pk.pub_key());

        let msg = b"hello world";
        let sig = sequ_pk.sign(msg);

        assert!(sig.verify(&sequ_pub_key, msg).is_ok());
    }

    #[test]
    fn test_k256_pub_key_serialization() {
        let pub_key = K256PrivateKey::generate().pub_key();
        let serialized_pub_key = borsh::to_vec(&pub_key).unwrap();

        let deserialized_pub_key: K256PublicKey =
            BorshDeserialize::try_from_slice(&serialized_pub_key).unwrap();
        assert_eq!(pub_key, deserialized_pub_key)
    }

    #[test]
    fn test_pub_key_serialization() {
        let pub_key = DefaultPrivateKey::generate().pub_key();
        let serialized_pub_key = borsh::to_vec(&pub_key).unwrap();

        let deserialized_pub_key: DefaultPublicKey =
            BorshDeserialize::try_from_slice(&serialized_pub_key).unwrap();
        assert_eq!(pub_key, deserialized_pub_key)
    }

    #[test]
    fn test_k256_signature_serialization() {
        let msg = [1; 32];
        let priv_key = K256PrivateKey::generate();

        let sig = priv_key.sign(&msg);
        let serialized_sig = borsh::to_vec(&sig).unwrap();
        let deserialized_sig: K256Signature =
            BorshDeserialize::try_from_slice(&serialized_sig).unwrap();
        assert_eq!(sig, deserialized_sig);

        let pub_key = priv_key.pub_key();
        deserialized_sig.verify(&pub_key, &msg).unwrap()
    }

    #[test]
    fn test_signature_serialization() {
        let msg = [1; 32];
        let priv_key = DefaultPrivateKey::generate();

        let sig = priv_key.sign(&msg);
        let serialized_sig = borsh::to_vec(&sig).unwrap();
        let deserialized_sig: DefaultSignature =
            BorshDeserialize::try_from_slice(&serialized_sig).unwrap();
        assert_eq!(sig, deserialized_sig);

        let pub_key = priv_key.pub_key();
        deserialized_sig.verify(&pub_key, &msg).unwrap()
    }

    #[test]
    fn test_k256_hex_conversion() {
        let priv_key = K256PrivateKey::generate();
        let hex = priv_key.as_hex();
        let deserialized_pub_key = K256PrivateKey::from_hex(&hex).unwrap().pub_key();
        assert_eq!(priv_key.pub_key(), deserialized_pub_key)
    }

    #[test]
    fn test_hex_conversion() {
        let priv_key = DefaultPrivateKey::generate();
        let hex = priv_key.as_hex();
        let deserialized_pub_key = DefaultPrivateKey::from_hex(&hex).unwrap().pub_key();
        assert_eq!(priv_key.pub_key(), deserialized_pub_key)
    }
}
