use std::fmt;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::{BasicAddress, RollupAddress};

/// MockAddress is a wrapper around Vec<u8> to implement AddressTrait
#[derive(Debug, PartialEq, Clone, Eq, BorshDeserialize, BorshSerialize, Hash)]
pub struct MockAddress(pub Vec<u8>);

impl MockAddress {
    /// Create new MockAddress
    pub fn new(arr: [u8; 32]) -> Self {
        Self(arr.to_vec())
    }
}

impl BasicAddress for MockAddress {}
impl RollupAddress for MockAddress {}

impl FromStr for MockAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(hex::decode(s)?))
    }
}

impl fmt::Display for MockAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
        let hash = hex::encode(&self.0);
        write!(f, "{hash}")
    }
}

impl AsRef<[u8]> for MockAddress {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; 32]> for MockAddress {
    fn from(value: [u8; 32]) -> Self {
        Self(value.to_vec())
    }
}

impl<'a> TryFrom<&'a [u8]> for MockAddress {
    type Error = anyhow::Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.to_vec()))
    }
}

impl From<Vec<u8>> for MockAddress {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl Default for MockAddress {
    fn default() -> Self {
        Self(vec![0; 32])
    }
}

impl Serialize for MockAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            Serialize::serialize(&hex::encode(&self.0), serializer)
        } else {
            Serialize::serialize(&self.0, serializer)
        }
    }
}

impl<'de> Deserialize<'de> for MockAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let hex_addr: String = Deserialize::deserialize(deserializer)?;
            Ok(MockAddress::from_str(&hex_addr).map_err(serde::de::Error::custom)?)
        } else {
            let addr = <Vec<u8> as Deserialize>::deserialize(deserializer)?;
            Ok(MockAddress(addr))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_address_string() {
        let addr = MockAddress::from([3; 32]);
        let s = addr.to_string();
        let recovered_addr = s.parse::<MockAddress>().unwrap();
        assert_eq!(addr, recovered_addr);
    }
}
