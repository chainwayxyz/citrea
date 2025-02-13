use std::sync::Arc;

use sov_schema_db::DB;
use tables::{prune_soft_confirmation_status, prune_soft_confirmations_by_number};
use tracing::{debug, error};

use crate::pruning::types::PruningNodeType;

mod tables;

macro_rules! log_result_or_error {
    ($table:literal, $call:expr) => {{
        match $call {
            Ok(result) => {
                debug!("Deleted {} records from {}", $table, result);
            }
            Err(e) => {
                error!("Failed to prune {} ledger tables: {:?}", $table, e);
                return;
            }
        }
    }};
}

/// Prune ledger
pub(crate) fn prune_ledger(node_type: PruningNodeType, ledger_db: Arc<DB>, up_to_block: u64) {
    debug!("Pruning Ledger, up to L2 block {}", up_to_block);

    match node_type {
        PruningNodeType::Sequencer => {
            log_result_or_error!(
                "soft_confirmations_by_number",
                prune_soft_confirmations_by_number(node_type, &ledger_db, up_to_block)
            );
            log_result_or_error!(
                "soft_confirmation_status",
                prune_soft_confirmation_status(&ledger_db, up_to_block)
            );
        }
        PruningNodeType::FullNode => todo!(),
        PruningNodeType::BatchProver => todo!(),
        PruningNodeType::LightClient => todo!(),
    }
}
