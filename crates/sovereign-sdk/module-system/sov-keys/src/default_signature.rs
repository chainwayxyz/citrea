use std::fmt::Debug;
use std::hash::Hash;
#[cfg(feature = "native")]
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use sha2::Digest;

use crate::error::KeyError;
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
    use crate::error::KeyError;
    use crate::PrivateKey;

    #[derive(Clone)]
    pub struct K256PrivateKey {
        pub key_pair: SigningKey,
    }

    // TODO: Should we implement try_from_keypair? We can set private_key_length, public_key_length and keypair_length as constants which are 32,33,65 respectively

    impl TryFrom<&[u8]> for K256PrivateKey {
        type Error = KeyError;

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

        pub fn from_hex(hex: &str) -> Result<Self, KeyError> {
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
    type Error = KeyError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            pub_key: k256::ecdsa::VerifyingKey::from_sec1_bytes(value)?,
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

        let msg_sig = k256::ecdsa::Signature::from_slice(&buffer).map_err(map_error_k256)?;

        Ok(Self { msg_sig })
    }
}

impl BorshSerialize for K256Signature {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.msg_sig.to_bytes())
    }
}

impl std::fmt::Display for K256PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.pub_key.to_sec1_bytes()))
    }
}

impl TryFrom<&[u8]> for K256Signature {
    type Error = KeyError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            msg_sig: k256::ecdsa::Signature::from_slice(value)?,
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

#[cfg(feature = "native")]
fn map_error_k256(e: k256::ecdsa::signature::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}
#[cfg(not(feature = "native"))]
fn map_error_k256(_e: k256::ecdsa::signature::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, "Signature error")
}

#[cfg(feature = "native")]
impl FromStr for K256PublicKey {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pk_hex = &crate::pub_key_hex::PublicKeyHex::try_from(s)?;
        pk_hex.try_into()
    }
}

#[cfg(feature = "native")]
impl FromStr for K256Signature {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;

        let bytes: [u8; 64] = bytes.try_into().map_err(|_| Self::Err::InvalidSignature)?;

        Ok(K256Signature {
            msg_sig: k256::ecdsa::Signature::from_slice(&bytes)
                .map_err(|_| Self::Err::InvalidSignature)?,
        })
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use borsh::BorshDeserialize;

    use super::k256_private_key::K256PrivateKey;
    use crate::default_signature::{K256PublicKey, K256Signature};
    use crate::{PrivateKey, Signature};

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
    fn test_k256_hex_conversion() {
        let priv_key = K256PrivateKey::generate();
        let hex = priv_key.as_hex();
        let deserialized_pub_key = K256PrivateKey::from_hex(&hex).unwrap().pub_key();
        assert_eq!(priv_key.pub_key(), deserialized_pub_key)
    }
}
