use std::sync::Arc;

use citrea_common::NodeType;
use futures::future;
use ledger::rollback_ledger;
use native::rollback_native_db;
use sov_db::schema::tables::ProverLastScannedSlot;
use sov_db::schema::types::SlotNumber;
use sov_db::state_db::StateDB;
use state::rollback_state_db;
use tracing::info;
use types::RollbackContext;

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
        node_type: NodeType,
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
            rollback_ledger(node_type, ledger_db.clone(), context);
        });
        futures.push(ledger_rollback_handle);

        let ledger_db = self.ledger_db.clone();

        // If node is light client, the target version is the L1 height
        // as light client prover does not hold L2 state.
        let target_version = match node_type {
            NodeType::FullNode | NodeType::BatchProver | NodeType::Sequencer => {
                l2_target.map(|l2| l2 + 1)
            } // +1 because version = height + 1
            NodeType::LightClientProver => {
                if let Some(l1_target) = l1_target {
                    // Get highest state version from the state DB
                    let state_db_last_version = StateDB::new(state_db.clone())
                        .next_version()
                        .saturating_sub(1);

                    let last_scanned_l1_height = ledger_db
                        .get::<ProverLastScannedSlot>(&())?
                        .unwrap_or(SlotNumber(0))
                        .0;

                    if last_scanned_l1_height < l1_target {
                        // If the last scanned L1 height is less than the target, we cannot rollback
                        return Err(anyhow::anyhow!(
                            "Cannot rollback to L1 height {} as the last scanned height is {}",
                            l1_target,
                            last_scanned_l1_height
                        ));
                    }

                    if last_scanned_l1_height == 0 {
                        // If no slots have been scanned, we can rollback to the target version
                        info!("No rollback needed: no L1 slots have been scanned.");
                        return Ok(());
                    }

                    if last_scanned_l1_height <= state_db_last_version {
                        unreachable!("Last scanned L1 height should not be less than or equal to the last state DB version");
                    }

                    // This is done because the state DB version will start from 0 but the L1 height starts from a random value
                    // We take the difference with the last scanned l1 height and the target l1 height we want to rollback to
                    // and subtract it from the latest state DB version to get the target state version.
                    let difference = last_scanned_l1_height.saturating_sub(l1_target);
                    let target_version = state_db_last_version.saturating_sub(difference);

                    Some(target_version)
                } else {
                    None
                }
            }
        };

        if let Some(target_version) = target_version {
            let state_db_rollback_handle =
                tokio::task::spawn_blocking(move || rollback_state_db(state_db, target_version));

            futures.push(state_db_rollback_handle);

            let native_db_rollback_handle =
                tokio::task::spawn_blocking(move || rollback_native_db(native_db, target_version));

            futures.push(native_db_rollback_handle);
        };

        future::join_all(futures).await;

        Ok(())
    }
}
