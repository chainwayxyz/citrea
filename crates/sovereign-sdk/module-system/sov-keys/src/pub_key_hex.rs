use derive_more::Display;

/// A hexadecimal representation of a PublicKey.
use crate::{default_signature::K256PublicKey, error::KeyError};

#[derive(
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshDeserialize,
    borsh::BorshSerialize,
    Debug,
    PartialEq,
    Clone,
    Eq,
    Display,
)]
#[serde(try_from = "String", into = "String")]
#[display("{}", hex)]
pub struct PublicKeyHex {
    hex: String,
}

impl TryFrom<&str> for PublicKeyHex {
    type Error = KeyError;

    fn try_from(hex: &str) -> Result<Self, Self::Error> {
        Self::try_from(hex.to_owned())
    }
}

impl TryFrom<String> for PublicKeyHex {
    type Error = KeyError;

    fn try_from(hex: String) -> Result<Self, Self::Error> {
        if hex.len() & 1 != 0 {
            return Err(Self::Error::HexConversion("odd input length".to_string()));
        }

        if let Some((index, c)) = hex.chars().enumerate().find(|(_, c)| {
            !(matches!(c, '0'..='9' | 'a'..='f') || matches!(c, '0'..='9' | 'A'..='F'))
        }) {
            return Err(Self::Error::HexConversion(format!(
                "wrong character `{c}` at index {index}"
            )));
        }

        Ok(Self { hex })
    }
}

impl From<PublicKeyHex> for String {
    fn from(pub_key: PublicKeyHex) -> Self {
        pub_key.hex
    }
}

impl From<&K256PublicKey> for PublicKeyHex {
    fn from(pub_key: &K256PublicKey) -> Self {
        let hex = hex::encode(pub_key.pub_key.to_sec1_bytes());
        Self { hex }
    }
}

impl TryFrom<&PublicKeyHex> for K256PublicKey {
    type Error = KeyError;

    fn try_from(pub_key: &PublicKeyHex) -> Result<Self, Self::Error> {
        let bytes = hex::decode(&pub_key.hex)?;

        let bytes: [u8; 33] = bytes
            .try_into()
            .map_err(|_| Self::Error::InvalidPublicKey)?;

        let pub_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(bytes.as_ref())
            .map_err(|_| Self::Error::InvalidPublicKey)?;

        Ok(K256PublicKey { pub_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::default_signature::k256_private_key::K256PrivateKey;
    use crate::PrivateKey;

    #[test]
    fn test_k256_pub_key_hex() {
        let pub_key = K256PrivateKey::generate().pub_key();
        let pub_key_hex = PublicKeyHex::from(&pub_key);
        let converted_pub_key = K256PublicKey::try_from(&pub_key_hex).unwrap();
        assert_eq!(pub_key, converted_pub_key);
    }

    #[test]
    fn test_k256_pub_key_hex_str() {
        let key = "0300c27ad8a28f9e69f72984612c435edef385907101315f0317f0632a73aa706a";
        let pub_key_hex_lower: PublicKeyHex = key.try_into().unwrap();
        let pub_key_hex_upper: PublicKeyHex = key.to_uppercase().try_into().unwrap();

        let pub_key_lower = K256PublicKey::try_from(&pub_key_hex_lower).unwrap();
        let pub_key_upper = K256PublicKey::try_from(&pub_key_hex_upper).unwrap();

        assert_eq!(pub_key_lower, pub_key_upper)
    }

    #[test]
    fn test_bad_k256_pub_key_hex_str() {
        let key = "0300c27ad8a28f9e69f72984612c435edef385907101315f0317f0632a73aa706Z";
        let err = PublicKeyHex::try_from(key).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Bad hex conversion: wrong character `Z` at index 65"
        );

        let key = "030";
        let err = PublicKeyHex::try_from(key).unwrap_err();

        assert_eq!(err.to_string(), "Bad hex conversion: odd input length")
    }

    #[test]
    fn test_bad_pub_key_hex_str() {
        let key = "022e229198d957Zf0c0a504e7d7bcec99a1d62cccc7861ed2452676ad0323ad8";
        let err = PublicKeyHex::try_from(key).unwrap_err();

        assert_eq!(
            err.to_string(),
            "Bad hex conversion: wrong character `Z` at index 14"
        );

        let key = "022";
        let err = PublicKeyHex::try_from(key).unwrap_err();

        assert_eq!(err.to_string(), "Bad hex conversion: odd input length")
    }
}
