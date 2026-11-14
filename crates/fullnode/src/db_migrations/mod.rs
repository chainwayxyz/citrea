//! Database migrations for the fullnode
//!
//! This module manages database schema migrations for the fullnode's ledger database.
//! It provides functionality to smoothly upgrade the database schema when needed.

use bitcoin_da::db_migrations::ReencodeShortHeaderProofs;
use citrea_primitives::risc0_cutoff::risc0_cutoff;
use sov_db::ledger_db::migrations::{LedgerMigration, Migrations};
use sov_rollup_interface::Network;

/// Migration to rescan L1 from the RISC0 cutoff for the SP1 batch proofs v2 discarded
mod rescan_l1_after_risc0_cutoff;

pub(crate) use rescan_l1_after_risc0_cutoff::RescanL1AfterRisc0Cutoff;

/// Returns the list of database migrations to apply on `network`.
///
/// [`RescanL1AfterRisc0Cutoff`] needs the network's RISC0 cutoff. Without one, or without a
/// network as `citrea-cli db-migrate` runs them, it is left out of the list, so it isn't
/// recorded as executed and runs when the node starts with the cutoff.
pub fn migrations(network: Option<Network>) -> Migrations {
    let mut migrations: Vec<Box<dyn LedgerMigration + Send + Sync + 'static>> =
        vec![Box::new(ReencodeShortHeaderProofs)];
    if let Some(cutoff) = network.and_then(risc0_cutoff) {
        migrations.push(Box::new(RescanL1AfterRisc0Cutoff {
            l0: cutoff.l1_height(),
        }));
    }
    // The migrator takes a static list, built once per node start
    Box::leak(Box::new(migrations))
}
