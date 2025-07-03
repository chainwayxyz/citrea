use bitcoin::address::ParseError;
use bitcoincore_rpc::Error as BitcoinRpcError;
use thiserror::Error;
use tokio::task::JoinError;

use crate::monitoring::{MonitorError, TxStatus};

/// The top level error type that can be returned by the `BitcoinService`.
#[derive(Error, Debug)]
pub enum BitcoinServiceError {
    /// Fail to parse address.
    #[error("Fail to parse address: {0}")]
    AddressParseError(#[from] ParseError),
    /// Invalid transaction.
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    /// Task join error.
    #[error("Task join error: {0}")]
    JoinError(#[from] JoinError),
    /// Minimum relay fee not met.
    #[error("Transaction rejected: minimum relay fee not met")]
    MinRelayFeeNotMet,
    /// Transaction rejected by mempool.
    #[error("Transaction rejected by mempool: {0}")]
    MempoolRejection(String),
    /// There are no UTXOs.
    #[error("There are no UTXOs")]
    MissingUTXO,
    /// There are no spendable UTXOs.
    #[error("There are no spendable UTXOs")]
    MissingSpendableUTXO,
    /// Missing previous UTXOs.
    #[error("Missing previous UTXOs")]
    MissingPreviousUTXO,
    /// Monitoring error.
    #[error("Monitoring error: {0}")]
    MonitorError(#[from] MonitorError),
    /// Couldn't finalize psbt.
    #[error("Couldn't finalize psbt")]
    PsbtFinalizationFailure,
    /// Bitcoin RPC error.
    #[error("Bitcoin RPC error: {0}")]
    RpcError(#[from] BitcoinRpcError),
    /// Cannot bump fee for TX.
    #[error("Cannot bump fee for TX with status: {0:?}. Transaction must be pending")]
    WrongStatusForBumping(TxStatus),
    /// Other error.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
