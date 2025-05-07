use std::sync::Arc;

use futures::future;
use native::rollback_native_db;
use state::rollback_state_db;
use tracing::{debug, info};

use crate::types::StorageNodeType;

mod ledger;
mod native;
mod node;
pub mod service;
mod state;

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
        _current_l2_height: u64,
        l2_target: u64,
        l1_target: u64,
        last_sequencer_commitment_index: u32,
    ) -> anyhow::Result<()> {
        info!(
            "Rolling back {} node until L2 {}, L1 {}",
            node_type, l2_target, l1_target
        );

        let ledger_db = self.ledger_db.clone();
        let native_db = self.native_db.clone();
        let state_db = self.state_db.clone();

        let ledger_rollback_handle = tokio::task::spawn_blocking(move || {
            debug!(
                "Rolling back {}, down to L2 block {}, L1 block {}",
                node_type, l2_target, l1_target
            );
            match node_type {
                StorageNodeType::Sequencer => node::rollback_sequencer(
                    ledger_db,
                    l2_target,
                    l1_target,
                    last_sequencer_commitment_index,
                ),
                StorageNodeType::FullNode => node::rollback_fullnode(
                    ledger_db,
                    l2_target,
                    l1_target,
                    last_sequencer_commitment_index,
                ),
                StorageNodeType::BatchProver => node::rollback_batch_prover(
                    ledger_db,
                    l2_target,
                    l1_target,
                    last_sequencer_commitment_index,
                ),
                StorageNodeType::LightClient => {
                    node::rollback_light_client(ledger_db, l2_target, l1_target)
                }
            }
        });

        let state_db_rollback_handle =
            tokio::task::spawn_blocking(move || rollback_state_db(state_db, l2_target));

        let native_db_rollback_handle =
            tokio::task::spawn_blocking(move || rollback_native_db(native_db, l2_target));

        future::join_all([
            ledger_rollback_handle,
            state_db_rollback_handle,
            native_db_rollback_handle,
        ])
        .await;

        Ok(())
    }
}
