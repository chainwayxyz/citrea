// https://github.com/paradigmxyz/reth/blob/main/crates/rpc/rpc-types/src/eth/block.rs
use std::hash::Hash;
use std::{
    fmt::{self},
    num::ParseIntError,
    str::FromStr,
};

use alloy_primitives::U64;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A block Number (or tag - "latest", "earliest", "pending")
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum BlockNumberOrTag {
    /// Latest block
    #[default]
    Latest,
    /// Finalized block accepted as canonical
    Finalized,
    /// Safe head block
    Safe,
    /// Earliest block (genesis)
    Earliest,
    /// Pending block (not yet part of the blockchain)
    Pending,
    /// Block by number from canon chain
    Number(u64),
}

impl BlockNumberOrTag {
    /// Returns the numeric block number if explicitly set
    pub const fn as_number(&self) -> Option<u64> {
        match *self {
            BlockNumberOrTag::Number(num) => Some(num),
            _ => None,
        }
    }

    /// Returns `true` if a numeric block number is set
    pub const fn is_number(&self) -> bool {
        matches!(self, BlockNumberOrTag::Number(_))
    }

    /// Returns `true` if it's "latest"
    pub const fn is_latest(&self) -> bool {
        matches!(self, BlockNumberOrTag::Latest)
    }

    /// Returns `true` if it's "finalized"
    pub const fn is_finalized(&self) -> bool {
        matches!(self, BlockNumberOrTag::Finalized)
    }

    /// Returns `true` if it's "safe"
    pub const fn is_safe(&self) -> bool {
        matches!(self, BlockNumberOrTag::Safe)
    }

    /// Returns `true` if it's "pending"
    pub const fn is_pending(&self) -> bool {
        matches!(self, BlockNumberOrTag::Pending)
    }

    /// Returns `true` if it's "earliest"
    pub const fn is_earliest(&self) -> bool {
        matches!(self, BlockNumberOrTag::Earliest)
    }
}

impl From<u64> for BlockNumberOrTag {
    fn from(num: u64) -> Self {
        BlockNumberOrTag::Number(num)
    }
}

impl From<U64> for BlockNumberOrTag {
    fn from(num: U64) -> Self {
        num.to::<u64>().into()
    }
}

impl Serialize for BlockNumberOrTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            BlockNumberOrTag::Number(ref x) => serializer.serialize_str(&format!("0x{x:x}")),
            BlockNumberOrTag::Latest => serializer.serialize_str("latest"),
            BlockNumberOrTag::Finalized => serializer.serialize_str("finalized"),
            BlockNumberOrTag::Safe => serializer.serialize_str("safe"),
            BlockNumberOrTag::Earliest => serializer.serialize_str("earliest"),
            BlockNumberOrTag::Pending => serializer.serialize_str("pending"),
        }
    }
}

impl<'de> Deserialize<'de> for BlockNumberOrTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?.to_lowercase();
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl FromStr for BlockNumberOrTag {
    type Err = ParseBlockNumberError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let block = match s {
            "latest" => Self::Latest,
            "finalized" => Self::Finalized,
            "safe" => Self::Safe,
            "earliest" => Self::Earliest,
            "pending" => Self::Pending,
            _number => {
                if let Some(hex_val) = s.strip_prefix("0x") {
                    let number = u64::from_str_radix(hex_val, 16);
                    BlockNumberOrTag::Number(number?)
                } else {
                    return Err(HexStringMissingPrefixError::default().into());
                }
            }
        };
        Ok(block)
    }
}

impl fmt::Display for BlockNumberOrTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockNumberOrTag::Number(ref x) => format!("0x{x:x}").fmt(f),
            BlockNumberOrTag::Latest => f.write_str("latest"),
            BlockNumberOrTag::Finalized => f.write_str("finalized"),
            BlockNumberOrTag::Safe => f.write_str("safe"),
            BlockNumberOrTag::Earliest => f.write_str("earliest"),
            BlockNumberOrTag::Pending => f.write_str("pending"),
        }
    }
}

/// Error variants when parsing a [BlockNumberOrTag]
#[derive(Debug, thiserror::Error)]
pub enum ParseBlockNumberError {
    /// Failed to parse hex value
    #[error(transparent)]
    ParseIntErr(#[from] ParseIntError),
    /// Block numbers should be 0x-prefixed
    #[error(transparent)]
    MissingPrefix(#[from] HexStringMissingPrefixError),
}

/// Thrown when a 0x-prefixed hex string was expected
#[derive(Copy, Clone, Debug, Default, thiserror::Error)]
#[non_exhaustive]
#[error("hex string without 0x prefix")]
pub struct HexStringMissingPrefixError;
