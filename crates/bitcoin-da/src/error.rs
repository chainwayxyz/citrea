//! This module provides the error types for the Bitcoin DA service.

use bitcoin::address::ParseError;
use bitcoincore_rpc::Error as BitcoinRpcError;
use thiserror::Error;
use tokio::task::JoinError;

use crate::monitoring::{MonitorError, TxStatus};

/// The top level error type that can be returned by the `BitcoinService`.
#[derive(Error, Debug)]
pub enum BitcoinServiceError {
    /// Fail to parse address.
    #[error("Failed to parse address: {0}")]
    AddressParseError(#[from] ParseError),
    /// Invalid transaction.
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    /// Task join error.
    #[error("Task join error: {0}")]
    JoinError(#[from] JoinError),
    /// There are no UTXOs.
    #[error("There are no UTXOs")]
    MissingUTXO,
    /// There are no spendable UTXOs.
    #[error("There are no spendable UTXOs")]
    MissingSpendableUTXO,
    /// Missing previous UTXOs.
    #[error("Missing previous UTXOs")]
    MissingPreviousUTXO,
    /// Fee calculation fails to meet min relay fee
    #[error("Fee calculation error. Doesn't meet min relay fee rate of {0}")]
    FeeCalculation(u64),
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
    /// Tx requeste when queue is not empty.
    #[error("Cannot create DA transaction while da queue is not empty")]
    QueueNotEmpty,
    /// Transaction rejected by mempool.
    #[error(transparent)]
    MempoolRejection(#[from] MempoolRejection),
    /// Other error.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Error type for mempool rejections via testmempoolaccept method.
#[derive(Error, Debug)]
pub enum MempoolRejection {
    /// Minimum relay fee not met.
    #[error("Transaction rejected: minimum relay fee not met")]
    MinRelayFeeNotMet,
    /// Sent package of txs resulted in too much unconfirmed tx data in mempool. (over 101 kvb)
    #[error("Transaction rejected: package-too-large")]
    PackageTooLarge,
    /// Sent package of txs resulted in too many transactions in mempool. (ascendant/descendant limit)
    #[error("Transaction rejected: package-too-many-transactions")]
    PackageTooManyTransactions,
    /// Sent package of txs resulted in too many transactions in mempool. (ascendant/descendant limit)
    #[error("Transaction rejected: package-mempool-limits")]
    PackageMempoolLimits,
    #[error("Transaction rejected: too-long-mempool-chain")]
    /// Sent package of txs resulted in too long mempool chain. (ascendant/descendant limit)
    TooLongMempoolChain,
    /// Other mempool rejection reason.
    #[error("Transaction rejected by mempool: {0}")]
    Other(String),
}

impl MempoolRejection {
    /// Creates the error from a bitcoin rpc reason string.
    pub fn from_reason(reason: String) -> Self {
        if reason.contains("min relay fee not met") {
            MempoolRejection::MinRelayFeeNotMet
        } else if reason.contains("package-too-large") {
            MempoolRejection::PackageTooLarge
        } else if reason.contains("package-too-many-transactions") {
            MempoolRejection::PackageTooManyTransactions
        } else if reason.contains("package-mempool-limits") {
            MempoolRejection::PackageMempoolLimits
        } else if reason.contains("too-long-mempool-chain") {
            MempoolRejection::TooLongMempoolChain
        } else {
            MempoolRejection::Other(reason.to_string())
        }
    }

    /// Mempool rejection variants that are recoverable by re-trying on a new block and dependent on mempool state such as too many transactions in mempool or package too large
    pub fn should_be_queued(&self) -> bool {
        matches!(
            self,
            Self::PackageTooLarge | Self::PackageMempoolLimits | Self::PackageTooManyTransactions
        )
    }
}
