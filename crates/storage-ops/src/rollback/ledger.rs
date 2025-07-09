use std::sync::Arc;

use citrea_common::NodeType;
use sov_db::schema::tables::{
    BATCH_PROVER_LEDGER_TABLES, FULL_NODE_LEDGER_TABLES, LIGHT_CLIENT_PROVER_LEDGER_TABLES,
    SEQUENCER_LEDGER_TABLES,
};
use sov_schema_db::DB;
use tracing::{debug, error, info, warn};

use super::types::RollbackContext;
use crate::rollback::node::batch_prover::BatchProverLedgerRollback;
use crate::rollback::node::fullnode::FullNodeLedgerRollback;
use crate::rollback::node::light_client::LightClientLedgerRollback;
use crate::rollback::node::sequencer::SequencerLedgerRollback;
use crate::rollback::types::LedgerNodeRollback;

pub fn rollback_ledger(node_type: NodeType, ledger_db: Arc<DB>, context: RollbackContext) {
    debug!(
        "Rolling back {}, down to L2 block {:?}, L1 block {:?}",
        node_type, context.l2_target, context.l1_target
    );
    let (tables, rollback_result) = match node_type {
        NodeType::Sequencer => {
            let sequencer_rollback = SequencerLedgerRollback::new(ledger_db);
            (SEQUENCER_LEDGER_TABLES, sequencer_rollback.execute(context))
        }
        NodeType::FullNode => {
            let fullnode_rollback = FullNodeLedgerRollback::new(ledger_db);
            (FULL_NODE_LEDGER_TABLES, fullnode_rollback.execute(context))
        }
        NodeType::BatchProver => {
            let batch_prover_rollback = BatchProverLedgerRollback::new(ledger_db);
            (
                BATCH_PROVER_LEDGER_TABLES,
                batch_prover_rollback.execute(context),
            )
        }
        NodeType::LightClientProver => {
            let light_client_rollback = LightClientLedgerRollback::new(ledger_db);
            (
                LIGHT_CLIENT_PROVER_LEDGER_TABLES,
                light_client_rollback.execute(context),
            )
        }
    };

    let rollback_result = match rollback_result {
        Ok(result) => result,
        Err(e) => {
            error!("Rollback failure: {:?}", e);
            return;
        }
    };

    for table in tables {
        if let Some(table_result) = rollback_result.processed_tables.get(table) {
            info!("Deleted {} records from {}", table_result, table);
        } else {
            warn!(
                "Table {} was not rolled back, advise to look into this ASAP",
                table
            );
        }
    }
}
