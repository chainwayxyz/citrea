#![forbid(unsafe_code)]

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub mod client;

/// A 32-byte hash [`serde`]-encoded as a hex string optionally prefixed with
/// `0x`. See [`sov_rollup_interface::rpc::utils::rpc_hex`].
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct HexHash(#[serde(with = "sov_rollup_interface::rpc::utils::rpc_hex")] pub [u8; 32]);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize)]
pub struct HexOrNum(pub u64);

impl<'de> Deserialize<'de> for HexOrNum {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;

        match value {
            Value::Number(num) => num
                .as_u64()
                .map(Self)
                .ok_or_else(|| serde::de::Error::custom("Invalid number")),
            Value::String(s) => {
                let without_prefix = s.trim_start_matches("0x");
                u64::from_str_radix(without_prefix, 16)
                    .map(Self)
                    .map_err(|e| serde::de::Error::custom(format!("Invalid hex string: {}", e)))
            }
            _ => Err(serde::de::Error::custom("Expected number or hex string")),
        }
    }
}

impl From<u64> for HexOrNum {
    fn from(v: u64) -> Self {
        HexOrNum(v)
    }
}

impl From<HexOrNum> for u64 {
    fn from(v: HexOrNum) -> Self {
        v.0
    }
}
