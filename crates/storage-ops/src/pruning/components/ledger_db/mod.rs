use std::sync::Arc;

use slots::prune_slots;
use soft_confirmations::prune_soft_confirmations;
use sov_schema_db::DB;
use tracing::debug;

use crate::log_result_or_error;
use crate::pruning::types::StorageNodeType;

mod slots;
mod soft_confirmations;

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
