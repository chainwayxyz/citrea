use std::sync::Arc;

use l2_blocks::prune_l2_blocks;
use slots::prune_slots;
use sov_schema_db::DB;
use tracing::debug;

use crate::log_result_or_error;
use crate::types::StorageNodeType;

mod l2_blocks;
mod slots;

/// Prune ledger
pub(crate) fn prune_ledger(node_type: StorageNodeType, ledger_db: Arc<DB>, up_to_block: u64) {
    debug!("Pruning Ledger, up to L2 block {}", up_to_block);

    match node_type {
        StorageNodeType::Sequencer => {
            log_result_or_error!(
                "l2_blocks",
                prune_l2_blocks(node_type, &ledger_db, up_to_block)
            );
            log_result_or_error!("slots", prune_slots(node_type, &ledger_db, up_to_block));
        }
        StorageNodeType::FullNode => {
            log_result_or_error!(
                "l2_blocks",
                prune_l2_blocks(node_type, &ledger_db, up_to_block)
            );
            log_result_or_error!("slots", prune_slots(node_type, &ledger_db, up_to_block));
        }
        StorageNodeType::BatchProver => {
            log_result_or_error!(
                "l2_blocks",
                prune_l2_blocks(node_type, &ledger_db, up_to_block)
            );
            log_result_or_error!("slots", prune_slots(node_type, &ledger_db, up_to_block));
        }
        StorageNodeType::LightClient => {
            log_result_or_error!(
                "l2_blocks",
                prune_l2_blocks(node_type, &ledger_db, up_to_block)
            );
            log_result_or_error!("slots", prune_slots(node_type, &ledger_db, up_to_block));
        }
    }
}
