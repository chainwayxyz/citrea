use bitcoin::address::ParseError;
use bitcoincore_rpc::Error as BitcoinRpcError;
use thiserror::Error;
use tokio::task::JoinError;

use crate::monitoring::{MonitorError, TxStatus};

#[derive(Error, Debug)]
pub enum BitcoinServiceError {
    #[error("Fail to parse address: {0}")]
    AddressParseError(#[from] ParseError),
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("Task join error: {0}")]
    JoinError(#[from] JoinError),
    #[error("Transaction rejected: minimum relay fee not met")]
    MinRelayFeeNotMet,
    #[error("Transaction rejected by mempool: {0}")]
    MempoolRejection(String),
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
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
