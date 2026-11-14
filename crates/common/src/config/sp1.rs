//! Configuration for SP1 proving.
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::utils::read_env;
use crate::FromEnv;

/// Configuration for SP1Host.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct SP1HostConfig {
    /// Optional backup directory for proof inputs.
    pub tx_backup_dir: Option<PathBuf>,
    /// Prices and timeouts of Succinct prover network requests.
    #[serde(default)]
    pub network_request: NetworkRequestConfig,
}

impl FromEnv for SP1HostConfig {
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            tx_backup_dir: std::env::var("TX_BACKUP_DIR").ok().map(PathBuf::from),
            network_request: NetworkRequestConfig::from_env()?,
        })
    }
}

/// Succinct prover network requests offer a percent of the network's suggested price per PGU:
/// 120% at first, raised by `no_bid_raise_percent` after each request no prover bid on, up to
/// `max_price_percent`, and never above `max_usd_per_billion_pgu`.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
pub struct NetworkRequestConfig {
    /// Percent the offer is multiplied by after a request no prover bid on. Above 100.
    #[serde(default = "default_no_bid_raise_percent")]
    pub no_bid_raise_percent: u64,
    /// Highest offer, as a percent of the network's suggested price. At least 120.
    #[serde(default = "default_max_price_percent")]
    pub max_price_percent: u64,
    /// Highest offer in USD per billion PGU, at the network's PROVE/USD price. Requests wait
    /// while the network's floor is above it or its price is unknown. Above 0.
    #[serde(default = "default_max_usd_per_billion_pgu")]
    pub max_usd_per_billion_pgu: f64,
    /// Seconds a request waits for a bid before it is cancelled and resubmitted. Longer than
    /// `min_auction_period_secs`, since no request is assigned before that period ends.
    #[serde(default = "default_auction_timeout_secs")]
    pub auction_timeout_secs: u64,
    /// Seconds after submission before a request can be assigned: its auction settles once this
    /// period has passed and a prover has bid. Longer lets more provers bid.
    #[serde(default = "default_min_auction_period_secs")]
    pub min_auction_period_secs: u64,
    /// Percent of the gas-based deadline a request gets: twice what a 5M PGU/s prover needs,
    /// at least 40 minutes. Capped at the network's 24 hours. Above 0.
    #[serde(default = "default_deadline_percent")]
    pub deadline_percent: u64,
}

#[inline]
const fn default_no_bid_raise_percent() -> u64 {
    150
}

/// 4x the first offer.
#[inline]
const fn default_max_price_percent() -> u64 {
    480
}

#[inline]
const fn default_max_usd_per_billion_pgu() -> f64 {
    5.0
}

#[inline]
const fn default_auction_timeout_secs() -> u64 {
    60
}

/// Succinct recommends 10-15 s for better prices.
#[inline]
const fn default_min_auction_period_secs() -> u64 {
    15
}

#[inline]
const fn default_deadline_percent() -> u64 {
    100
}

impl Default for NetworkRequestConfig {
    fn default() -> Self {
        Self {
            no_bid_raise_percent: default_no_bid_raise_percent(),
            max_price_percent: default_max_price_percent(),
            max_usd_per_billion_pgu: default_max_usd_per_billion_pgu(),
            auction_timeout_secs: default_auction_timeout_secs(),
            min_auction_period_secs: default_min_auction_period_secs(),
            deadline_percent: default_deadline_percent(),
        }
    }
}

/// Reads `key`, or `default` if it is unset. Unparsable values stop the node rather than fall
/// back to the default.
fn read_or<T: std::str::FromStr>(key: &str, default: T) -> anyhow::Result<T>
where
    T::Err: std::fmt::Display,
{
    read_env(key)
        .ok()
        .map(|value| value.parse())
        .transpose()
        .map_err(|error| anyhow::anyhow!("{key}: {error}"))
        .map(|value| value.unwrap_or(default))
}

impl FromEnv for NetworkRequestConfig {
    fn from_env() -> anyhow::Result<Self> {
        let read = read_or::<u64>;
        Ok(Self {
            no_bid_raise_percent: read("SP1_NO_BID_RAISE_PERCENT", default_no_bid_raise_percent())?,
            max_price_percent: read("SP1_MAX_PRICE_PERCENT", default_max_price_percent())?,
            max_usd_per_billion_pgu: read_or(
                "SP1_MAX_USD_PER_BILLION_PGU",
                default_max_usd_per_billion_pgu(),
            )?,
            auction_timeout_secs: read("SP1_AUCTION_TIMEOUT_SECS", default_auction_timeout_secs())?,
            min_auction_period_secs: read(
                "SP1_MIN_AUCTION_PERIOD_SECS",
                default_min_auction_period_secs(),
            )?,
            deadline_percent: read("SP1_DEADLINE_PERCENT", default_deadline_percent())?,
        })
    }
}
