//! This module defines the trait that is used to build batches of transactions.

extern crate alloc;

use alloc::vec::Vec;

use crate::spec::SpecId;

/// BlockBuilder trait is responsible for managing mempool and building batches.
pub trait BatchBuilder {
    /// Accept a new transaction.
    /// Can return error if transaction is invalid or mempool is full.
    fn accept_tx(&mut self, tx: Vec<u8>) -> anyhow::Result<()>;

    /// Builds a new batch out of transactions in mempool.
    /// Logic of which transactions and how many of them is included in batch is up to implementation.
    fn get_next_blob(&mut self, current_spec: SpecId) -> anyhow::Result<Vec<Vec<u8>>>;
}
