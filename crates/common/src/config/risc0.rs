use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::utils::{is_dev_mode_enabled_via_environment, read_env};
use crate::FromEnv;

/// Boundless storage configuration for S3
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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

impl FromEnv for BoundlessS3StorageConfig {
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
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BoundlessPinataStorageConfig {
    /// Pinata JWT for authentication
    pub pinata_jwt: String,
    /// Pinata API URL
    pub pinata_api_url: String,
    /// IPFS Gateway URL
    pub ipfs_gateway_url: String,
}

impl FromEnv for BoundlessPinataStorageConfig {
    fn from_env() -> anyhow::Result<Self> {
        let pinata_jwt = read_env("BOUNDLESS_PINATA_JWT")?;
        let pinata_api_url = read_env("BOUNDLESS_PINATA_API_URL")?;
        let ipfs_gateway_url = read_env("BOUNDLESS_IPFS_GATEWAY_URL")?;

        Ok(Self {
            pinata_jwt,
            pinata_api_url,
            ipfs_gateway_url,
        })
    }
}

/// Boundless storage configuration
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BoundlessStorageConfig {
    /// S3 storage provider
    S3(BoundlessS3StorageConfig),
    /// Pinata storage provider
    Pinata(BoundlessPinataStorageConfig),
}

/// Configuration for the Boundless prover
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BoundlessProverConfig {
    /// Boundless configuration
    pub boundless: BoundlessConfig,
    /// Storage configuration
    pub storage: BoundlessStorageConfig,
}

impl FromEnv for BoundlessProverConfig {
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

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
/// Configuration for the Boundless Market client
pub struct BoundlessConfig {
    pub wallet_private_key: String,
    pub rpc_url: String,
    pub is_offchain: bool,
}

impl FromEnv for BoundlessConfig {
    fn from_env() -> anyhow::Result<Self> {
        let wallet_private_key = read_env("BOUNDLESS_WALLET_PRIVATE_KEY")?;
        let rpc_url = read_env("BOUNDLESS_RPC_URL")?;
        let is_offchain = read_env("BOUNDLESS_IS_OFFCHAIN")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        Ok(Self {
            wallet_private_key,
            rpc_url,
            is_offchain,
        })
    }
}

/// Configuration for the local (IPC) prover
#[derive(Debug, Clone, Deserialize, Serialize, Default, PartialEq, Eq)]
pub struct LocalProverConfig {
    /// Optional path to the r0vm binary
    pub r0vm_path: Option<PathBuf>,
    /// Enable dev mode
    #[serde(default)]
    pub dev_mode: bool,
}

impl FromEnv for LocalProverConfig {
    fn from_env() -> anyhow::Result<Self> {
        let r0vm_path = read_env("RISC0_SERVER_PATH").ok().map(PathBuf::from);
        let dev_mode = is_dev_mode_enabled_via_environment();

        Ok(Self {
            r0vm_path,
            dev_mode,
        })
    }
}

/// Configuration for the Bonsai prover
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BonsaiProverConfig {
    /// Bonsai API URL
    pub api_url: String,
    /// Bonsai API key
    pub api_key: String,
}

impl FromEnv for BonsaiProverConfig {
    fn from_env() -> anyhow::Result<Self> {
        let api_url = read_env("BONSAI_API_URL")?;
        let api_key = read_env("BONSAI_API_KEY")?;
        Ok(Self { api_url, api_key })
    }
}

/// Prover configuration enum
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
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

impl FromEnv for Risc0ProverConfig {
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
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Risc0HostConfig {
    /// Prover config
    pub prover: Risc0ProverConfig,
    /// Optional backup directory for transaction data
    pub tx_backup_dir: Option<PathBuf>,
}

impl FromEnv for Risc0HostConfig {
    fn from_env() -> anyhow::Result<Self> {
        let prover = Risc0ProverConfig::from_env()?;
        let tx_backup_dir = std::env::var("TX_BACKUP_DIR").ok().map(PathBuf::from);

        Ok(Self {
            prover,
            tx_backup_dir,
        })
    }
}
