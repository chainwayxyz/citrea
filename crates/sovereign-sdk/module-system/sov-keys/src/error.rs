use thiserror::Error;

/// sov-keys error
#[derive(Debug, Error)]
pub enum KeyError {
    #[error("Bad hex conversion: {0}")]
    HexConversion(String),

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Hex decode error: {0}")]
    HexDecodeError(#[from] hex::FromHexError),

    #[error("ECDSA error: {0}")]
    EcdsaError(#[from] k256::ecdsa::Error),

    #[error("{0}")]
    Other(String),
}
