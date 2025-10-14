use std::str::FromStr;

use anyhow::Context;
use boundless_market::alloy::signers::k256::ecdsa::SigningKey;
use boundless_market::alloy::signers::local::{LocalSigner, PrivateKeySigner};
use boundless_market::deployments::BASE;
use boundless_market::storage::{PinataStorageProvider, S3StorageProvider};
use boundless_market::{Deployment, StandardStorageProvider};
use citrea_common::utils::read_env;
use citrea_common::FromEnv;
use url::Url;

/// Boundless storage configuration for S3
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
        let s3_use_presigned = read_env("BOUNDLESS_S3_NO_PRESIGNED").is_err();

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

/// Boundless storage configuration for S3
pub struct BoundlessPinataStorageConfig {
    /// Pinata JWT for authentication
    pub pinata_jwt: String,
    /// Pinata API URL
    pub pinata_api_url: Url,
    /// IPFS Gateway URL
    pub ipfs_gateway_url: Url,
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

/// Get the boundless storage provider based on the environment configuration
pub async fn get_boundless_builtin_storage_provider() -> anyhow::Result<StandardStorageProvider> {
    let storage_config = if let Ok(config) = BoundlessS3StorageConfig::from_env() {
        StandardStorageProvider::S3(S3StorageProvider::from_parts(
            config.s3_access_key.clone(),
            config.s3_secret_key.clone(),
            config.s3_bucket.clone(),
            config.s3_url.clone(),
            config.aws_region.clone(),
            config.s3_use_presigned,
        ))
    } else if let Ok(config) = BoundlessPinataStorageConfig::from_env() {
        StandardStorageProvider::Pinata(
            PinataStorageProvider::from_parts(
                config.pinata_jwt.clone(),
                config.pinata_api_url.to_string(),
                config.ipfs_gateway_url.to_string(),
            )
            .await?,
        )
    } else {
        return Err(anyhow::anyhow!(
            "No valid storage configuration found for boundless, provide either S3 or Pinata configuration"
        ));
    };
    Ok(storage_config)
}

#[derive(Debug, Clone)]
/// Configuration for the Boundless Market client
pub struct BoundlessConfig {
    pub(crate) wallet_private_key: LocalSigner<SigningKey>,
    pub(crate) rpc_url: Url,
    pub(crate) deployment: Deployment,
    #[allow(dead_code)]
    pub(crate) is_offchain: bool,
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
            is_offchain,
        })
    }
}
