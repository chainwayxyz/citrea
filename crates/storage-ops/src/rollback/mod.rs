use std::sync::Arc;

use components::{rollback_ledger_db, rollback_native_db, rollback_state_db};
use futures::future;
use tracing::info;

mod components;
pub mod service;

pub struct Rollback {
    /// Access to ledger tables.
    ledger_db: Arc<sov_schema_db::DB>,
    /// Access to native DB.
    native_db: Arc<sov_schema_db::DB>,
    /// Access to state DB.
    state_db: Arc<sov_schema_db::DB>,
}

impl Rollback {
    pub fn new(
        ledger_db: Arc<sov_schema_db::DB>,
        state_db: Arc<sov_schema_db::DB>,
        native_db: Arc<sov_schema_db::DB>,
    ) -> Self {
        // distance is the only criteria implemented at the moment.
        Self {
            ledger_db,
            state_db,
            native_db,
        }
    }

    /// Rollback the provided number of blocks
    pub async fn execute(&self, current_l2_height: u64, num_blocks: u64) -> anyhow::Result<()> {
        info!("Rolling back by {} blocks", num_blocks);

        let ledger_db = self.ledger_db.clone();
        let native_db = self.native_db.clone();
        let state_db = self.state_db.clone();

        let down_to_block = current_l2_height - num_blocks + 1;

        let ledger_rollback_handle =
            tokio::task::spawn_blocking(move || rollback_ledger_db(ledger_db, down_to_block));

        let state_db_rollback_handle =
            tokio::task::spawn_blocking(move || rollback_state_db(state_db, down_to_block));

        let native_db_rollback_handle =
            tokio::task::spawn_blocking(move || rollback_native_db(native_db, down_to_block));

        future::join_all([
            ledger_rollback_handle,
            state_db_rollback_handle,
            native_db_rollback_handle,
        ])
        .await;

        Ok(())
    }
}
