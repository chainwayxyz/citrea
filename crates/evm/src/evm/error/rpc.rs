//! Implementation specific Errors for the `eth_` namespace.

use jsonrpsee::types::ErrorObject;
use reth_primitives::{Bytes, U256};
use reth_rpc::eth::error::{EthResult, RevertError, RpcInvalidTransactionError};
use revm::primitives::{ExecutionResult, HaltReason, OutOfGasError};

use super::pool::{
    Eip4844PoolTransactionError, InvalidPoolTransactionError, PoolError, PoolErrorKind,
    PoolTransactionError,
};
use super::result::internal_rpc_err;

// /// Eth Optimism Api Error
// #[cfg(feature = "optimism")]
// #[derive(Debug, thiserror::Error)]
// pub enum OptimismEthApiError {
//     /// Wrapper around a [hyper::Error].
//     #[error(transparent)]
//     HyperError(#[from] hyper::Error),
//     /// Wrapper around an [reqwest::Error].
//     #[error(transparent)]
//     HttpError(#[from] reqwest::Error),
//     /// Thrown when serializing transaction to forward to sequencer
//     #[error("invalid sequencer transaction")]
//     InvalidSequencerTransaction,
//     /// Thrown when calculating L1 gas fee
//     #[error("failed to calculate l1 gas fee")]
//     L1BlockFeeError,
//     /// Thrown when calculating L1 gas used
//     #[error("failed to calculate l1 gas used")]
//     L1BlockGasError,
// }

// impl From<JsInspectorError> for EthApiError {
//     fn from(error: JsInspectorError) -> Self {
//         match error {
//             err @ JsInspectorError::JsError(_) => {
//                 EthApiError::InternalJsTracerError(err.to_string())
//             }
//             err => EthApiError::InvalidParams(err.to_string()),
//         }
//     }
// }

// /// Optimism specific invalid transaction errors
// #[cfg(feature = "optimism")]
// #[derive(thiserror::Error, Debug)]
// pub enum OptimismInvalidTransactionError {
//     /// A deposit transaction was submitted as a system transaction post-regolith.
//     #[error("no system transactions allowed after regolith")]
//     DepositSystemTxPostRegolith,
//     /// A deposit transaction halted post-regolith
//     #[error("deposit transaction halted after regolith")]
//     HaltedDepositPostRegolith,
// }

/// A helper error type that's mainly used to mirror `geth` Txpool's error messages
#[derive(Debug, thiserror::Error)]
pub enum RpcPoolError {
    /// When the transaction is already known
    #[error("already known")]
    AlreadyKnown,
    /// When the sender is invalid
    #[error("invalid sender")]
    InvalidSender,
    /// When the transaction is underpriced
    #[error("transaction underpriced")]
    Underpriced,
    /// When the transaction pool is full
    #[error("txpool is full")]
    TxPoolOverflow,
    /// When the replacement transaction is underpriced
    #[error("replacement transaction underpriced")]
    ReplaceUnderpriced,
    /// When the transaction exceeds the block gas limit
    #[error("exceeds block gas limit")]
    ExceedsGasLimit,
    /// When a negative value is encountered
    #[error("negative value")]
    NegativeValue,
    /// When oversized data is encountered
    #[error("oversized data")]
    OversizedData,
    /// When the max initcode size is exceeded
    #[error("max initcode size exceeded")]
    ExceedsMaxInitCodeSize,
    /// Errors related to invalid transactions
    #[error(transparent)]
    Invalid(#[from] RpcInvalidTransactionError),
    /// Custom pool error
    #[error(transparent)]
    PoolTransactionError(Box<dyn PoolTransactionError>),
    /// Eip-4844 related error
    #[error(transparent)]
    Eip4844(#[from] Eip4844PoolTransactionError),
    /// Thrown if a conflicting transaction type is already in the pool
    ///
    /// In other words, thrown if a transaction with the same sender that violates the exclusivity
    /// constraint (blob vs normal tx)
    #[error("address already reserved")]
    AddressAlreadyReserved,
    /// Other unspecified error
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl From<RpcPoolError> for ErrorObject<'static> {
    fn from(error: RpcPoolError) -> Self {
        match error {
            RpcPoolError::Invalid(err) => err.into(),
            error => internal_rpc_err(error.to_string()),
        }
    }
}

impl From<PoolError> for RpcPoolError {
    fn from(err: PoolError) -> RpcPoolError {
        match err.kind {
            PoolErrorKind::ReplacementUnderpriced => RpcPoolError::ReplaceUnderpriced,
            PoolErrorKind::FeeCapBelowMinimumProtocolFeeCap(_) => RpcPoolError::Underpriced,
            PoolErrorKind::SpammerExceededCapacity(_) => RpcPoolError::TxPoolOverflow,
            PoolErrorKind::DiscardedOnInsert => RpcPoolError::TxPoolOverflow,
            PoolErrorKind::InvalidTransaction(err) => err.into(),
            PoolErrorKind::Other(err) => RpcPoolError::Other(err),
            PoolErrorKind::AlreadyImported => RpcPoolError::AlreadyKnown,
            PoolErrorKind::ExistingConflictingTransactionType(_, _) => {
                RpcPoolError::AddressAlreadyReserved
            }
        }
    }
}

impl From<InvalidPoolTransactionError> for RpcPoolError {
    fn from(err: InvalidPoolTransactionError) -> RpcPoolError {
        match err {
            InvalidPoolTransactionError::Consensus(err) => RpcPoolError::Invalid(err.into()),
            InvalidPoolTransactionError::ExceedsGasLimit(_, _) => RpcPoolError::ExceedsGasLimit,
            InvalidPoolTransactionError::ExceedsMaxInitCodeSize(_, _) => {
                RpcPoolError::ExceedsMaxInitCodeSize
            }
            InvalidPoolTransactionError::IntrinsicGasTooLow => {
                RpcPoolError::Invalid(RpcInvalidTransactionError::GasTooLow)
            }
            InvalidPoolTransactionError::OversizedData(_, _) => RpcPoolError::OversizedData,
            InvalidPoolTransactionError::Underpriced => RpcPoolError::Underpriced,
            InvalidPoolTransactionError::Other(err) => RpcPoolError::PoolTransactionError(err),
            InvalidPoolTransactionError::Eip4844(err) => RpcPoolError::Eip4844(err),
            InvalidPoolTransactionError::Overdraft => {
                RpcPoolError::Invalid(RpcInvalidTransactionError::InsufficientFunds)
            }
        }
    }
}

/// Errors returned from a sign request.
#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// Error occured while trying to sign data.
    #[error("could not sign")]
    CouldNotSign,
    /// Signer for requested account not found.
    #[error("unknown account")]
    NoAccount,
    /// TypedData has invalid format.
    #[error("given typed data is not valid")]
    InvalidTypedData,
    /// Invalid transaction request in `sign_transaction`.
    #[error("invalid transaction request")]
    InvalidTransactionRequest,
    /// No chain ID was given.
    #[error("no chainid")]
    NoChainId,
}

// #[allow(clippy::unconditional_recursion)]
// impl From<SignError> for ErrorObject<'static> {
//     fn from(error: SignError) -> Self {
//         error.into()
//     }
// }

/// We have to implement these functions because they are private to the reth_rpc crate
pub trait RpcInvalidTransactionErrorExt {
    /// Converts the out of gas error
    fn out_of_gas(reason: OutOfGasError, gas_limit: u64) -> RpcInvalidTransactionError {
        let gas_limit = U256::from(gas_limit);
        match reason {
            OutOfGasError::Basic => RpcInvalidTransactionError::BasicOutOfGas(gas_limit),
            OutOfGasError::Memory => RpcInvalidTransactionError::MemoryOutOfGas(gas_limit),
            OutOfGasError::Precompile => RpcInvalidTransactionError::PrecompileOutOfGas(gas_limit),
            OutOfGasError::InvalidOperand => {
                RpcInvalidTransactionError::InvalidOperandOutOfGas(gas_limit)
            }
            OutOfGasError::MemoryLimit => RpcInvalidTransactionError::MemoryOutOfGas(gas_limit),
        }
    }

    /// Converts the halt error
    ///
    /// Takes the configured gas limit of the transaction which is attached to the error
    fn halt(reason: HaltReason, gas_limit: u64) -> RpcInvalidTransactionError {
        match reason {
            HaltReason::OutOfGas(err) => Self::out_of_gas(err, gas_limit),
            HaltReason::NonceOverflow => RpcInvalidTransactionError::NonceMaxValue,
            err => RpcInvalidTransactionError::EvmHalt(err),
        }
    }
}

impl RpcInvalidTransactionErrorExt for RpcInvalidTransactionError {}

/// Converts the evm [ExecutionResult] into a result where `Ok` variant is the output bytes if it is
/// [ExecutionResult::Success].
pub(crate) fn ensure_success(result: ExecutionResult) -> EthResult<Bytes> {
    match result {
        ExecutionResult::Success { output, .. } => Ok(output.into_data()),
        ExecutionResult::Revert { output, .. } => {
            Err(RpcInvalidTransactionError::Revert(RevertError::new(output)).into())
        }
        ExecutionResult::Halt { reason, gas_used } => {
            Err(RpcInvalidTransactionError::halt(reason, gas_used).into())
        }
    }
}
