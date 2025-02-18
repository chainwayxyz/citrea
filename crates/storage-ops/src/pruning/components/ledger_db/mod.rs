use std::sync::Arc;

use sov_schema_db::DB;
use tracing::{debug, error};

use self::slots::prune_slots;
use self::soft_confirmations::prune_soft_confirmations;
use crate::pruning::types::StorageNodeType;

mod slots;
mod soft_confirmations;

macro_rules! log_result_or_error {
    ($tables_group:literal, $call:expr) => {{
        match $call {
            Ok(result) => {
                debug!("Deleted {} records from {} group", result, $tables_group);
            }
            Err(e) => {
                error!(
                    "Failed to prune ledger's {} table group: {:?}",
                    $tables_group, e
                );
                return;
            }
        }
    }};
}

/// Prune ledger
pub(crate) fn prune_ledger(node_type: StorageNodeType, ledger_db: Arc<DB>, up_to_block: u64) {
    debug!("Pruning Ledger, up to L2 block {}", up_to_block);

    match node_type {
        StorageNodeType::Sequencer => {
            log_result_or_error!(
                "soft_confirmations",
                prune_soft_confirmations(node_type, &ledger_db, up_to_block)
            );
            log_result_or_error!("slots", prune_slots(node_type, &ledger_db, up_to_block));
        }
        StorageNodeType::FullNode => {
            log_result_or_error!(
                "soft_confirmations",
                prune_soft_confirmations(node_type, &ledger_db, up_to_block)
            );
            log_result_or_error!("slots", prune_slots(node_type, &ledger_db, up_to_block));
        }
        StorageNodeType::BatchProver => {
            log_result_or_error!(
                "soft_confirmations",
                prune_soft_confirmations(node_type, &ledger_db, up_to_block)
            );
            log_result_or_error!("slots", prune_slots(node_type, &ledger_db, up_to_block));
        }
        StorageNodeType::LightClient => {
            log_result_or_error!(
                "soft_confirmations",
                prune_soft_confirmations(node_type, &ledger_db, up_to_block)
            );
            log_result_or_error!("slots", prune_slots(node_type, &ledger_db, up_to_block));
        }
    }
}
