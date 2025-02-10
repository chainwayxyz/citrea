use std::sync::Arc;

use futures::future;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::SharedLedgerOps;
use tracing::info;

use self::components::{prune_ledger, prune_native_db, prune_state_db};
use self::criteria::{Criteria, DistanceCriteria};
pub use self::service::*;

pub(crate) mod components;
pub(crate) mod criteria;
pub(crate) mod service;

/// A configuration type to define the behaviour of the pruner.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PruningConfig {
    /// Defines the number of blocks from the tip of the chain to remove.
    pub distance: u64,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self { distance: 256 }
    }
}

pub struct Pruner<DB>
where
    DB: SharedLedgerOps,
{
    /// Access to ledger tables.
    ledger_db: DB,
    /// Access to native DB.
    native_db: Arc<sov_schema_db::DB>,
    /// Access to state DB.
    state_db: Arc<sov_schema_db::DB>,
    /// Criteria to decide pruning
    criteria: Box<dyn Criteria + Send + Sync>,
}

impl<DB> Pruner<DB>
where
    DB: SharedLedgerOps + Send + Sync + Clone + 'static,
{
    pub fn new(
        config: PruningConfig,
        ledger_db: DB,
        state_db: Arc<sov_schema_db::DB>,
        native_db: Arc<sov_schema_db::DB>,
    ) -> Self {
        // distance is the only criteria implemented at the moment.
        let criteria = Box::new(DistanceCriteria {
            distance: config.distance,
        });
        Self {
            ledger_db,
            native_db,
            state_db,
            criteria,
        }
    }

    pub fn store_last_pruned_l2_height(&self, last_pruned_l2_height: u64) -> anyhow::Result<()> {
        self.ledger_db
            .set_last_pruned_l2_height(last_pruned_l2_height)
    }

    pub(crate) fn should_prune(
        &self,
        last_pruned_l2_height: u64,
        current_l2_height: u64,
    ) -> Option<u64> {
        self.criteria
            .should_prune(last_pruned_l2_height, current_l2_height)
    }

    /// Prune everything
    pub async fn prune(&self, up_to_block: u64) {
        info!("Pruning up to L2 block: {}", up_to_block);
        let ledger_db = self.ledger_db.clone();
        let native_db = self.native_db.clone();
        let state_db = self.state_db.clone();

        let ledger_pruning_handle =
            tokio::task::spawn_blocking(move || prune_ledger(ledger_db, up_to_block));

        let state_db_pruning_handle =
            tokio::task::spawn_blocking(move || prune_state_db(state_db, up_to_block));

        let native_db_pruning_handle =
            tokio::task::spawn_blocking(move || prune_native_db(native_db, up_to_block));

        future::join_all([
            ledger_pruning_handle,
            state_db_pruning_handle,
            native_db_pruning_handle,
        ])
        .await;
    }
}
