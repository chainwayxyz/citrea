use bitcoin::address::ParseError;
use bitcoincore_rpc::Error as BitcoinRpcError;
use thiserror::Error;
use tokio::task::JoinError;

use crate::monitoring::{MonitorError, TxStatus};

#[derive(Error, Debug)]
pub enum BitcoinServiceError {
    #[error("Failed to parse address: {0}")]
    AddressParseError(#[from] ParseError),
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("Task join error: {0}")]
    JoinError(#[from] JoinError),
    #[error("There are no UTXOs")]
    MissingUTXO,
    #[error("There are no spendable UTXOs")]
    MissingSpendableUTXO,
    #[error("Missing previous UTXOs")]
    MissingPreviousUTXO,
    #[error("Monitoring error: {0}")]
    MonitorError(#[from] MonitorError),
    #[error("Couldn't finalize psbt")]
    PsbtFinalizationFailure,
    #[error("Bitcoin RPC error: {0}")]
    RpcError(#[from] BitcoinRpcError),
    #[error("Cannot bump fee for TX with status: {0:?}. Transaction must be pending")]
    WrongStatusForBumping(TxStatus),
    #[error("Cannot create DA transaction while da queue is not empty")]
    QueueNotEmpty,
    #[error(transparent)]
    MempoolRejection(#[from] MempoolRejection),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Error, Debug)]
pub enum MempoolRejection {
    #[error("Transaction rejected: minimum relay fee not met")]
    MinRelayFeeNotMet,
    #[error("Transaction rejected: package-too-large")]
    PackageTooLarge,
    #[error("Transaction rejected: package-too-many-transactions")]
    PackageTooManyTransactions,
    #[error("Transaction rejected: package-mempool-limits")]
    PackageMempoolLimits,
    #[error("Transaction rejected by mempool: {0}")]
    Other(String),
}

impl MempoolRejection {
    pub fn from_reason(reason: String) -> Self {
        if reason.contains("min relay fee not met") {
            MempoolRejection::MinRelayFeeNotMet
        } else if reason.contains("package-too-large") {
            MempoolRejection::PackageTooLarge
        } else if reason.contains("package-too-many-transactions") {
            MempoolRejection::PackageTooManyTransactions
        } else if reason.contains("package-mempool-limits") {
            MempoolRejection::PackageMempoolLimits
        } else {
            MempoolRejection::Other(reason.to_string())
        }
    }

    // Mempool rejection variants that are recoverable by re-trying on a new block and dependent on mempool state such as too many transactions in mempool or package too large
    pub fn should_be_queued(&self) -> bool {
        matches!(
            self,
            Self::PackageTooLarge | Self::PackageMempoolLimits | Self::PackageTooManyTransactions
        )
    }
}
