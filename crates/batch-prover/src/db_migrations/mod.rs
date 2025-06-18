//! Database migrations for the batch prover
//!
//! This module manages database schema migrations for the batch prover's ledger database.
//! It provides functionality to smoothly upgrade the database schema when needed.

use std::sync::OnceLock;

use sov_db::ledger_db::migrations::LedgerMigration;

/// Returns the list of database migrations to apply
///
/// This function returns a static reference to a vector of migrations that should be
/// applied to upgrade the database schema. The migrations are lazily initialized
/// using a thread-safe once cell.
///
/// # Returns
/// A reference to a vector of boxed migration implementations
pub fn migrations() -> &'static Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> {
    static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync + 'static>>> =
        OnceLock::new();
    MIGRATIONS.get_or_init(std::vec::Vec::new)
}
