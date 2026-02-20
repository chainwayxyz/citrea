use std::sync::Arc;
use std::time::Instant;

use citrea_common::NodeType;
use l2_blocks::prune_l2_blocks;
use reth_tasks::shutdown::GracefulShutdown;
use slots::prune_slots;
use sov_schema_db::DB;
use tracing::info;

use crate::log_result_or_error;

mod l2_blocks;
mod slots;

/// Prune ledger
pub(crate) fn prune_ledger_db(
    node_type: NodeType,
    ledger_db: Arc<DB>,
    up_to_block: u64,
    shutdown_signal: Option<&GracefulShutdown>,
) -> anyhow::Result<()> {
    info!("Pruning Ledger, up to L2 block {}", up_to_block);
    let start = Instant::now();

    match node_type {
        NodeType::Sequencer => {
            log_result_or_error!(
                "l2_blocks",
                prune_l2_blocks(node_type, &ledger_db, up_to_block, shutdown_signal)
            );
            log_result_or_error!(
                "slots",
                prune_slots(node_type, &ledger_db, up_to_block, shutdown_signal)
            );
        }
        NodeType::FullNode => {
            log_result_or_error!(
                "l2_blocks",
                prune_l2_blocks(node_type, &ledger_db, up_to_block, shutdown_signal)
            );
            log_result_or_error!(
                "slots",
                prune_slots(node_type, &ledger_db, up_to_block, shutdown_signal)
            );
        }
        NodeType::BatchProver => {
            log_result_or_error!(
                "l2_blocks",
                prune_l2_blocks(node_type, &ledger_db, up_to_block, shutdown_signal)
            );
            log_result_or_error!(
                "slots",
                prune_slots(node_type, &ledger_db, up_to_block, shutdown_signal)
            );
        }
        NodeType::LightClientProver => {
            log_result_or_error!(
                "slots",
                prune_slots(node_type, &ledger_db, up_to_block, shutdown_signal)
            );
        }
    }

    let duration = start.elapsed();
    info!(
        "Ledger pruning completed, node_type={:?}, up_to_block={}, duration={}ms",
        node_type,
        up_to_block,
        duration.as_millis()
    );
    Ok(())
}
