use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use boundless_market::alloy::signers::k256::ecdsa::SigningKey;
use boundless_market::alloy::signers::local::{LocalSigner, PrivateKeySigner};
use boundless_market::deployments::BASE;
use boundless_market::Deployment;
use citrea_common::utils::read_env;
use serde::{Deserialize, Serialize};
use url::Url;

/// Boundless storage configuration for S3
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BoundlessS3StorageConfig {
    /// S3 access key
    pub s3_access_key: String,
    /// S3 secret key
    pub s3_secret_key: String,
    /// S3 bucket
    pub s3_bucket: String,
    /// S3 URL
    pub s3_url: String,
    /// S3 region
    pub aws_region: String,
    /// Use presigned URLs for S3
    pub s3_use_presigned: bool,
}

impl citrea_common::FromEnv for BoundlessS3StorageConfig {
    fn from_env() -> anyhow::Result<Self> {
        let s3_access_key = read_env("BOUNDLESS_S3_ACCESS_KEY")?;
        let s3_secret_key = read_env("BOUNDLESS_S3_SECRET_KEY")?;
        let s3_bucket = read_env("BOUNDLESS_S3_BUCKET")?;
        let s3_url = read_env("BOUNDLESS_S3_URL")?;
        let aws_region = read_env("BOUNDLESS_AWS_REGION")?;
        let s3_use_presigned = read_env("BOUNDLESS_S3_NO_PRESIGNED")
            .map(|s| s.eq_ignore_ascii_case("true") || s == "1")
            .unwrap_or(true);

        Ok(Self {
            s3_access_key,
            s3_secret_key,
            s3_bucket,
            s3_url,
            aws_region,
            s3_use_presigned,
        })
    }
}

/// Boundless storage configuration for Pinata
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BoundlessPinataStorageConfig {
    /// Pinata JWT for authentication
    pub pinata_jwt: String,
    /// Pinata API URL
    #[serde(with = "url_serde")]
    pub pinata_api_url: Url,
    /// IPFS Gateway URL
    #[serde(with = "url_serde")]
    pub ipfs_gateway_url: Url,
}

mod url_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use url::Url;

    pub fn serialize<S>(url: &Url, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        url.as_str().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Url, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Url::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl citrea_common::FromEnv for BoundlessPinataStorageConfig {
    fn from_env() -> anyhow::Result<Self> {
        let pinata_jwt = read_env("BOUNDLESS_PINATA_JWT")?;
        let pinata_api_url = read_env("BOUNDLESS_PINATA_API_URL")?;
        let ipfs_gateway_url = read_env("BOUNDLESS_IPFS_GATEWAY_URL")?;

        Ok(Self {
            pinata_jwt,
            pinata_api_url: Url::parse(&pinata_api_url).expect("Invalid Pinata API URL"),
            ipfs_gateway_url: Url::parse(&ipfs_gateway_url).expect("Invalid IPFS Gateway URL"),
        })
    }
}

/// Boundless storage configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BoundlessStorageConfig {
    /// S3 storage provider
    S3(BoundlessS3StorageConfig),
    /// Pinata storage provider
    Pinata(BoundlessPinataStorageConfig),
}

/// Configuration for the Boundless prover
#[derive(Debug, Clone)]
pub struct BoundlessProverConfig {
    /// Boundless configuration
    pub boundless: BoundlessConfig,
    /// Storage configuration
    pub storage: BoundlessStorageConfig,
}

impl citrea_common::FromEnv for BoundlessProverConfig {
    fn from_env() -> anyhow::Result<Self> {
        let boundless = BoundlessConfig::from_env()?;

        let storage = if let Ok(config) = BoundlessS3StorageConfig::from_env() {
            BoundlessStorageConfig::S3(config)
        } else if let Ok(config) = BoundlessPinataStorageConfig::from_env() {
            BoundlessStorageConfig::Pinata(config)
        } else {
            return Err(anyhow::anyhow!(
                "No valid storage configuration found for boundless, provide either S3 or Pinata configuration"
            ));
        };

        Ok(Self { boundless, storage })
    }
}

#[derive(Debug, Clone)]
/// Configuration for the Boundless Market client
pub struct BoundlessConfig {
    pub(crate) wallet_private_key: LocalSigner<SigningKey>,
    pub(crate) rpc_url: Url,
    pub(crate) deployment: Deployment,
}

impl citrea_common::FromEnv for BoundlessConfig {
    fn from_env() -> anyhow::Result<Self> {
        let wallet_private_key = read_env("BOUNDLESS_WALLET_PRIVATE_KEY")?;
        let rpc_url = read_env("BOUNDLESS_RPC_URL")?;
        let is_offchain = read_env("BOUNDLESS_IS_OFFCHAIN")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        // TODO: Switch to Deployment::builder after boundless 1.0 release to switch between base mainnet and sepolia
        let mut deployment = BASE;
        if !is_offchain {
            deployment.order_stream_url = None;
        }

        Ok(Self {
            wallet_private_key: PrivateKeySigner::from_str(&wallet_private_key)
                .context("Failed to parse wallet private key")?,
            rpc_url: Url::parse(&rpc_url).expect("Invalid RPC URL"),
            deployment,
        })
    }
}

/// Configuration for the local (IPC) prover
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LocalProverConfig {
    /// Optional path to the r0vm binary
    pub r0vm_path: Option<PathBuf>,
    /// Enable dev mode
    #[serde(default)]
    pub dev_mode: bool,
}

impl citrea_common::FromEnv for LocalProverConfig {
    fn from_env() -> anyhow::Result<Self> {
        let r0vm_path = read_env("RISC0_SERVER_PATH").ok().map(PathBuf::from);
        let dev_mode = crate::is_dev_mode_enabled_via_environment();
        Ok(Self {
            r0vm_path,
            dev_mode,
        })
    }
}

/// Configuration for the Bonsai prover
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BonsaiProverConfig {
    /// Bonsai API URL
    pub api_url: String,
    /// Bonsai API key
    pub api_key: String,
}

impl citrea_common::FromEnv for BonsaiProverConfig {
    fn from_env() -> anyhow::Result<Self> {
        let api_url = read_env("BONSAI_API_URL")?;
        let api_key = read_env("BONSAI_API_KEY")?;
        Ok(Self { api_url, api_key })
    }
}

/// Prover configuration enum
#[derive(Debug, Clone)]
pub enum Risc0ProverConfig {
    /// Local IPC prover
    Local(LocalProverConfig),
    /// Bonsai remote prover
    Bonsai(BonsaiProverConfig),
    /// Boundless market prover
    Boundless(Box<BoundlessProverConfig>),
}

impl Default for Risc0ProverConfig {
    fn default() -> Self {
        Self::Local(LocalProverConfig::default())
    }
}

impl citrea_common::FromEnv for Risc0ProverConfig {
    fn from_env() -> anyhow::Result<Self> {
        match std::env::var("RISC0_PROVER") {
            Ok(prover) => match prover.as_str() {
                "boundless" => Ok(Self::Boundless(
                    Box::new(BoundlessProverConfig::from_env()?),
                )),
                "bonsai" => Ok(Self::Bonsai(BonsaiProverConfig::from_env()?)),
                "ipc" | "local" => Ok(Self::Local(LocalProverConfig::from_env()?)),
                _ => Err(anyhow::anyhow!("Invalid prover specified: {prover}")),
            },
            Err(_) => {
                tracing::debug!("No prover specified, defaulting to local.");
                Ok(Self::Local(LocalProverConfig::from_env()?))
            }
        }
    }
}

/// Configuration for Risc0Host
#[derive(Debug, Clone, Default)]
pub struct Risc0HostConfig {
    /// Prover config
    pub prover: Risc0ProverConfig,
    /// Optional backup directory for transaction data
    pub tx_backup_dir: Option<PathBuf>,
}

impl citrea_common::FromEnv for Risc0HostConfig {
    fn from_env() -> anyhow::Result<Self> {
        let prover = Risc0ProverConfig::from_env()?;
        let tx_backup_dir = std::env::var("TX_BACKUP_DIR").ok().map(PathBuf::from);

        Ok(Self {
            prover,
            tx_backup_dir,
        })
    }
}
