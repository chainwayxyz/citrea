//! This module is the core of the Sovereign SDK. It defines the traits and types that
//! allow the SDK to run the "business logic" of any application generically.
//!
//! The most important trait in this module is the [`StateTransitionFunction`], which defines the
//! main event loop of the rollup.

use super::zk::StorageRootHash;
use crate::RefCount;

/// The configuration of a full node of the rollup which creates zk proofs.
pub struct ProverConfig;
/// The configuration used to initialize the "Verifier" of the state transition function
/// which runs inside of the zkVM.
pub struct ZkConfig;
/// The configuration of a standard full node of the rollup which does not create zk proofs
pub struct StandardConfig;

/// A special marker trait which allows us to define different rollup configurations. There are
/// only 3 possible instantiations of this trait: [`ProverConfig`], [`ZkConfig`], and [`StandardConfig`].
pub trait StateTransitionConfig: sealed::Sealed {}
impl StateTransitionConfig for ProverConfig {}
impl StateTransitionConfig for ZkConfig {}
impl StateTransitionConfig for StandardConfig {}

// https://rust-lang.github.io/api-guidelines/future-proofing.html
mod sealed {
    use super::{ProverConfig, StandardConfig, ZkConfig};

    pub trait Sealed {}
    impl Sealed for ProverConfig {}
    impl Sealed for ZkConfig {}
    impl Sealed for StandardConfig {}
}

/// A diff of the state, represented as a list of key-value pairs.
pub type StateDiff = Vec<(RefCount<[u8]>, Option<RefCount<[u8]>>)>;

/// Helper struct which contains initial and final state roots.
pub struct StateRootTransition {
    /// Initial state root
    pub init_root: StorageRootHash,
    /// Final state root
    pub final_root: StorageRootHash,
}

/// Result of applying a l2 block to current state
/// Where:
/// - S - generic for state root
/// - Cs - generic for change set
/// - T - generic for transaction receipt contents
/// - W - generic for witness
/// - Da - generic for DA layer
pub struct L2BlockResult<Cs, W, SL> {
    /// Contains state root before and after applying txs
    pub state_root_transition: StateRootTransition,
    /// Cache of the read and writes happened on the state.
    pub state_log: SL,
    /// Cache of the read and writes happened on the offchain state.
    pub offchain_log: SL,
    /// Container for all state alterations that happened during l2 block execution
    pub change_set: Cs,
    /// Witness after applying the whole block
    pub witness: W,
    /// Witness after applying the whole block
    pub offchain_witness: W,
    /// State diff after applying the whole block
    pub state_diff: StateDiff,
}

#[derive(Debug, PartialEq)]
/// Error in the l2 block itself
pub enum L2BlockError {
    /// The public key of the sequencer (known by a full node or prover) does not match
    /// the public key in the l2 block
    SequencerPublicKeyMismatch,
    /// The DA hash in the l2 block does not match the hash of the DA block provided
    InvalidDaHash,
    /// The DA tx commitment in the l2 block does not match the tx commitment of the DA block provided
    InvalidDaTxsCommitment,
    /// The hash of the l2 block is incorrect
    InvalidL2BlockHash,
    /// The l2 block signature is incorret
    InvalidL2BlockSignature,
    /// The l2 block includes a non-serializable sov-tx
    NonSerializableSovTx,
    /// The l2 block includes a sov-tx that can not be signature verified
    InvalidSovTxSignature,
    /// The l2 block includes a sov-tx that can not be runtime decoded
    SovTxCantBeRuntimeDecoded,
    /// The l2 block includes an invalid tx merkle root
    InvalidTxMerkleRoot,
    /// Any other error that can occur during the application of a l2 block
    /// These can come from runtime hooks etc.
    Other(String),
}

#[derive(Debug, PartialEq)]
/// Error that can occur during the runtime hook of a l2 block
pub enum L2BlockHookError {
    /// The nonce of the sov-tx is incorrect
    SovTxBadNonce,
    /// The account for the sov-tx does not exist
    SovTxAccountNotFound,
    /// The account for the sov-tx already exists
    SovTxAccountAlreadyExists,
    /// There are too many l2 blocks on a DA slot
    TooManyL2BlocksOnDaSlot,
    /// The timestamp of the l2 block is incorrect
    TimestampShouldBeGreater,
}

#[derive(Debug, PartialEq)]
/// Error that can occur during a module call of a l2 block
pub enum L2BlockModuleCallError {
    /// The EVM gas used exceeds the block gas limit
    EvmGasUsedExceedsBlockGasLimit {
        /// The cumulative gas used in the block
        /// at the point of the error
        cumulative_gas: u64,
        /// The gas used by the transaction
        /// that causes the error
        tx_gas_used: u64,
        /// The block gas limit
        block_gas_limit: u64,
    },
    /// There was an error during EVM transaction execution
    EvmTransactionExecutionError(String),
    /// There is a system transaction where it should not be
    EvmMisplacedSystemTx,
    /// Address does not have enough funds to pay for L1 fee
    EvmNotEnoughFundsForL1Fee,
    /// An EVM transaction in the l2 block was not serializable
    EvmTxNotSerializable,
    /// The sov-tx was not sent by the rule enforcer authority
    RuleEnforcerUnauthorized,
    /// The EVM transaction type is not supported
    EvmTxTypeNotSupported(String),
    /// Short Header Proof Not Found
    ShortHeaderProofNotFound,
    /// Short Header Proof Verification Error
    ShortHeaderProofVerificationError,
    /// Some System transaction was placed after a user transaction in the block
    EvmSystemTransactionPlacedAfterUserTx,
    /// System tx failed to parse
    EvmSystemTxParseError,
}

#[derive(Debug, PartialEq)]
/// Error that can occur during the state transition
pub enum StateTransitionError {
    /// An error in the l2 block itself
    L2BlockError(L2BlockError),
    /// An error in the runtime hook
    HookError(L2BlockHookError),
    /// An error in the module call
    ModuleCallError(L2BlockModuleCallError),
}

#[cfg(feature = "native")]
impl std::error::Error for L2BlockError {}

#[cfg(feature = "native")]
impl std::error::Error for L2BlockHookError {}

#[cfg(feature = "native")]
impl std::error::Error for L2BlockModuleCallError {}

#[cfg(feature = "native")]
impl std::error::Error for StateTransitionError {}

#[cfg(feature = "native")]
impl std::fmt::Display for L2BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L2BlockError::SequencerPublicKeyMismatch => {
                write!(f, "Sequencer public key mismatch")
            }
            L2BlockError::InvalidDaHash => write!(f, "Invalid DA hash"),
            L2BlockError::InvalidDaTxsCommitment => write!(f, "Invalid DA txs commitment"),
            L2BlockError::InvalidL2BlockHash => {
                write!(f, "Invalid l2 block hash")
            }
            L2BlockError::InvalidL2BlockSignature => {
                write!(f, "Invalid l2 block signature")
            }
            L2BlockError::Other(s) => write!(f, "Other error: {}", s),
            L2BlockError::NonSerializableSovTx => write!(f, "Non serializable sov tx"),
            L2BlockError::InvalidSovTxSignature => write!(f, "Invalid sov tx signature"),
            L2BlockError::SovTxCantBeRuntimeDecoded => {
                write!(f, "Sov tx can't be runtime decoded")
            }
            L2BlockError::InvalidTxMerkleRoot => {
                write!(f, "Invalid tx merkle root")
            }
        }
    }
}

#[cfg(feature = "native")]
impl std::fmt::Display for L2BlockHookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L2BlockHookError::SovTxBadNonce => write!(f, "SovTx bad nonce"),
            L2BlockHookError::SovTxAccountNotFound => write!(f, "SovTx account not found"),
            L2BlockHookError::SovTxAccountAlreadyExists => {
                write!(f, "SovTx account already exists")
            }
            L2BlockHookError::TooManyL2BlocksOnDaSlot => {
                write!(f, "Too many l2 blocks on DA slot")
            }
            L2BlockHookError::TimestampShouldBeGreater => {
                write!(f, "Timestamp should be greater")
            }
        }
    }
}

#[cfg(feature = "native")]
impl std::fmt::Display for L2BlockModuleCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L2BlockModuleCallError::EvmGasUsedExceedsBlockGasLimit {
                cumulative_gas,
                tx_gas_used,
                block_gas_limit,
            } => {
                write!(
                            f,
                            "EVM gas used exceeds block gas limit: cumulative_gas: {}, tx_gas_used: {}, block_gas_limit: {}",
                            cumulative_gas, tx_gas_used, block_gas_limit
                        )
            }
            L2BlockModuleCallError::EvmTransactionExecutionError(e) => {
                write!(f, "EVM transaction execution error: {:?}", e)
            }
            L2BlockModuleCallError::EvmMisplacedSystemTx => {
                write!(f, "EVM misplaced system tx")
            }
            L2BlockModuleCallError::EvmNotEnoughFundsForL1Fee => {
                write!(f, "EVM not enough funds for L1 fee")
            }
            L2BlockModuleCallError::EvmTxTypeNotSupported(msg) => {
                write!(f, "EVM tx type {} is not supported", msg)
            }
            L2BlockModuleCallError::RuleEnforcerUnauthorized => {
                write!(f, "Rule enforcer unauthorized")
            }
            L2BlockModuleCallError::EvmTxNotSerializable => {
                write!(f, "EVM tx not serializable")
            }
            L2BlockModuleCallError::ShortHeaderProofNotFound => {
                write!(f, "Short header proof not found")
            }
            L2BlockModuleCallError::ShortHeaderProofVerificationError => {
                write!(f, "Short header proof verification error")
            }
            L2BlockModuleCallError::EvmSystemTransactionPlacedAfterUserTx => {
                write!(f, "EVM system transaction placed after user tx")
            }
            L2BlockModuleCallError::EvmSystemTxParseError => {
                write!(f, "EVM system transaction parse error")
            }
        }
    }
}

#[cfg(feature = "native")]
impl std::fmt::Display for StateTransitionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateTransitionError::L2BlockError(e) => write!(f, "{}", e),
            StateTransitionError::HookError(e) => write!(f, "{}", e),
            StateTransitionError::ModuleCallError(e) => write!(f, "{}", e),
        }
    }
}
