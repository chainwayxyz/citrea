use std::sync::Arc;

use futures::future;
use ledger::rollback_ledger;
use native::rollback_native_db;
use state::rollback_state_db;
use tracing::info;
use types::RollbackContext;

use crate::types::StorageNodeType;

mod ledger;
mod native;
mod node;
pub mod service;
mod state;
mod types;

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

    /// Rollback the provided L2/L1 block combination.
    pub async fn execute(
        &self,
        node_type: StorageNodeType,
        l2_target: Option<u64>,
        l1_target: Option<u64>,
        last_sequencer_commitment_index: Option<u32>,
    ) -> anyhow::Result<()> {
        info!(
            "Rolling back {:?} node until L2 {:?}, L1 {:?}",
            node_type, l2_target, l1_target
        );

        let mut futures = Vec::with_capacity(3);

        let ledger_db = self.ledger_db.clone();
        let native_db = self.native_db.clone();
        let state_db = self.state_db.clone();

        let ledger_rollback_handle = tokio::task::spawn_blocking(move || {
            let context = RollbackContext {
                l2_target,
                l1_target,
                last_sequencer_commitment_index,
            };
            rollback_ledger(node_type, ledger_db, context);
        });
        futures.push(ledger_rollback_handle);

        if let Some(l2_target) = l2_target {
            let state_db_rollback_handle =
                tokio::task::spawn_blocking(move || rollback_state_db(state_db, l2_target));

            futures.push(state_db_rollback_handle);

            let native_db_rollback_handle =
                tokio::task::spawn_blocking(move || rollback_native_db(native_db, l2_target));

            futures.push(native_db_rollback_handle);
        };

        future::join_all(futures).await;

        Ok(())
    }
}
