//! This module provides the error types for the Bitcoin DA service.

use bitcoin::address::ParseError;
use bitcoincore_rpc::Error as BitcoinRpcError;
use thiserror::Error;
use tokio::task::JoinError;

use crate::fee::FeeServiceError;
use crate::monitoring::MonitorError;

/// The top level error type that can be returned by the `BitcoinService`.
#[derive(Error, Debug)]
pub enum BitcoinServiceError {
    /// Fail to parse address.
    #[error("Failed to parse address: {0}")]
    AddressParseError(#[from] ParseError),
    /// Task join error.
    #[error("Task join error: {0}")]
    JoinError(#[from] JoinError),
    /// Monitoring error.
    #[error("Monitoring error: {0}")]
    MonitorError(#[from] MonitorError),
    /// Bitcoin RPC error.
    #[error("Bitcoin RPC error: {0}")]
    RpcError(#[from] BitcoinRpcError),
    /// Failed to decompress chunk data.
    #[error("Failed to parse complete chunks")]
    ChunkDecompressionError,
    /// IO error when compressing blob.
    #[error("Failure to compress blob: {0}")]
    CompressionError(std::io::Error),
    /// Channel send error.
    #[error("Failed to send message through channel")]
    ChannelSendError,
    /// Tokio channel receive error.
    #[error("Failed to receive message from channel: {0}")]
    ChannelRecvError(#[from] tokio::sync::oneshot::error::RecvError),
    /// Bitcoin transaction encoding/decoding error.
    #[error("Transaction encoding error: {0}")]
    TransactionEncodingError(#[from] bitcoin::consensus::encode::Error),
    /// Bitcoin compact target parsing error.
    #[error("Compact target parsing error: {0}")]
    CompactTargetError(#[from] bitcoin::error::UnprefixedHexError),
    /// Chunk ordering validation error.
    #[error("Chunk ordering validation error: {0}")]
    ChunkOrderingError(String),
    /// Failed to get block information by hash.
    #[error("Failed to get block info for hash {hash:?}: {source}")]
    BlockInfoRequestError {
        /// Requested blockhash
        hash: bitcoin::BlockHash,
        /// Source bitcoincore_rpc error
        #[source]
        source: bitcoincore_rpc::Error,
    },
    /// Failure to get fee rate
    #[error("Failed to get fee rate")]
    FeeRateError,
    /// Fee service operation failure.
    #[error("Fee service error: {0}")]
    FeeServiceError(#[from] FeeServiceError),
    /// The external tx-sender client is not configured.
    #[error("tx-sender client is not configured (tx_sender_url is required for nodes that submit to DA)")]
    TxSenderNotConfigured,
    /// Other error.
    #[error(transparent)]
    Other(anyhow::Error),
}
