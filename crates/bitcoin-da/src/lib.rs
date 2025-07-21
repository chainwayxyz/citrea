#![warn(missing_docs)]

//! This module provides the Bitcoin Data Availability (DA) service.
//! It includes functionality for storing the data on DA, verifying Bitcoin headers, managing transactions, and interacting with the Bitcoin network.
//!
//! In general, this module is responsible for sending the data on the Bitcoin blockchain,
//! reading the data from the Bitcoin transactions, and verifying the Bitcoin headers and transactions
//! are valid.
//!
//! There are some important concepts to understand:
//!
//! - Commit-reveal pattern: The service uses a commit-reveal pattern.
//!   In order to store data on the Bitcoin blockchain, the service first commits to the data by creating a transaction that includes a hash of the data.
//!   Later, it reveals the data by creating another transaction that includes the actual data using the inscription pattern.
//!
//! - The inscription pattern is cheaper than the classical approach.
//!   And it may look like this:
//!     <pubkey>
//!     OP_CHECKSIG
//!     OP_FALSE
//!     OP_IF
//!       OP_PUSHDATA ...
//!       OP_PUSHDATA ...
//!       ...
//!     OP_ENDIF
//!
//! - In order to find our data in the Bitcoin blockchain, we use the `reveal_tx_prefix`.
//!   It is a prefix of the wtxid of the reveal transaction.
//!
//! - A relevant transaction is a transaction which wtxid starts from `reveal_tx_prefix` and
//!   it contains a script that we are able to parse according to our tx format.
//!
//! - In tests the `reveal_tx_prefix` is of 1 byte length, but in production it is of 2 bytes length.
//!   Because in production it's 2 bytes long, the probability of getting a random wtxid to match our prefix is 1/2^16.
//!   That's how we can ignore the transactions that do not start with our prefix.
//!   And it saves us from parsing all the transactions in the Bitcoin blockchain.
//!
//! - The process of finding the right wtxid prefix is called "mining".
//!   It is done by adding a nonce to the reveal script. Changing the nonce changes the wtxid of the transaction.
//!
//! - When dealing with the Bitcoin blocks, we can extract relevant transactions from the block
//!   along with their proofs.
//!
//! - An Inclusion proof is a proof that the block consists of only given wtxids.
//!
//! - A Completeness proof is a proof that we have all the relevant transactions in the block and we didn't
//!   ignore any relevant transaction (that starts with the given prefix).

pub mod helpers;
pub mod spec;

#[cfg(feature = "native")]
pub mod service;

#[cfg(feature = "native")]
pub mod tx_signer;

#[cfg(feature = "native")]
pub mod monitoring;

#[cfg(feature = "native")]
pub mod metrics;

#[cfg(feature = "native")]
pub mod error;
#[cfg(feature = "native")]
pub mod fee;

#[cfg(feature = "native")]
pub mod rpc;

#[cfg(feature = "testing")]
pub mod test_utils;

pub mod network_constants;

pub mod verifier;

#[cfg(feature = "native")]
/// The minimal dust value output in reveal txs.
pub const REVEAL_OUTPUT_AMOUNT: u64 = 546;

#[cfg(feature = "native")]
/// This is added to reveal output in order to bruteforce nonces for wtxid prefixes.
const REVEAL_OUTPUT_THRESHOLD: u64 = 2000;
