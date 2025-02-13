use ed25519_dalek::VerifyingKey as DalekPublicKey;

use crate::default_signature::{DefaultPublicKey, K256PublicKey};
use crate::PublicKeyHex;

impl serde::Serialize for DefaultPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serde::Serialize::serialize(&PublicKeyHex::from(self), serializer)
        } else {
            serde::Serialize::serialize(&self.pub_key, serializer)
        }
    }
}

impl<'de> serde::Deserialize<'de> for DefaultPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let pub_key_hex: PublicKeyHex = serde::Deserialize::deserialize(deserializer)?;
            Ok(DefaultPublicKey::try_from(&pub_key_hex).map_err(serde::de::Error::custom)?)
        } else {
            let pub_key: DalekPublicKey = serde::Deserialize::deserialize(deserializer)?;
            Ok(DefaultPublicKey { pub_key })
        }
    }
}

impl serde::Serialize for K256PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serde::Serialize::serialize(&PublicKeyHex::from(self), serializer)
        } else {
            serde::Serialize::serialize(&self.pub_key.to_sec1_bytes(), serializer)
        }
    }
}

impl<'de> serde::Deserialize<'de> for K256PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let pub_key_hex: PublicKeyHex = serde::Deserialize::deserialize(deserializer)?;
            Ok(K256PublicKey::try_from(&pub_key_hex).map_err(serde::de::Error::custom)?)
        } else {
            let pub_key: k256::ecdsa::VerifyingKey = serde::Deserialize::deserialize(deserializer)?;
            Ok(K256PublicKey { pub_key })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_k256_pub_key_json() {
        let pub_key_hex: PublicKeyHex =
            "0300c27ad8a28f9e69f72984612c435edef385907101315f0317f0632a73aa706a"
                .try_into()
                .unwrap();

        let pub_key = K256PublicKey::try_from(&pub_key_hex).unwrap();
        let pub_key_str: String = serde_json::to_string(&pub_key).unwrap();

        assert_eq!(
            pub_key_str,
            r#""0300c27ad8a28f9e69f72984612c435edef385907101315f0317f0632a73aa706a""#
        );

        let deserialized: K256PublicKey = serde_json::from_str(&pub_key_str).unwrap();
        assert_eq!(deserialized, pub_key);
    }

    #[test]
    fn test_pub_key_json() {
        let pub_key_hex: PublicKeyHex =
            "022e229198d957bf0c0a504e7d7bcec99a1d62cccc7861ed2452676ad0323ad8"
                .try_into()
                .unwrap();

        let pub_key = DefaultPublicKey::try_from(&pub_key_hex).unwrap();
        let pub_key_str: String = serde_json::to_string(&pub_key).unwrap();

        assert_eq!(
            pub_key_str,
            r#""022e229198d957bf0c0a504e7d7bcec99a1d62cccc7861ed2452676ad0323ad8""#
        );

        let deserialized: DefaultPublicKey = serde_json::from_str(&pub_key_str).unwrap();
        assert_eq!(deserialized, pub_key);
    }
}
