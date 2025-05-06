pub(crate) use backup::*;
use citrea_storage_ops::types::StorageNodeType;
use clap::ValueEnum;
pub(crate) use pending::*;
pub(crate) use prune::*;
pub(crate) use rollback::*;
use sov_db::schema::tables::{
    BATCH_PROVER_LEDGER_TABLES, FULL_NODE_LEDGER_TABLES, LIGHT_CLIENT_PROVER_LEDGER_TABLES,
    SEQUENCER_LEDGER_TABLES,
};

mod backup;
mod pending;
mod prune;
mod rollback;

#[derive(Copy, Clone, ValueEnum)]
pub enum StorageNodeTypeArg {
    Sequencer,
    FullNode,
    BatchProver,
    LightClient,
}

impl From<StorageNodeTypeArg> for StorageNodeType {
    fn from(value: StorageNodeTypeArg) -> Self {
        match value {
            StorageNodeTypeArg::Sequencer => StorageNodeType::Sequencer,
            StorageNodeTypeArg::FullNode => StorageNodeType::FullNode,
            StorageNodeTypeArg::BatchProver => StorageNodeType::BatchProver,
            StorageNodeTypeArg::LightClient => StorageNodeType::LightClient,
        }
    }
}

pub(crate) fn cfs_from_node_type(node_type: StorageNodeTypeArg) -> Vec<String> {
    let cfs = match node_type {
        StorageNodeTypeArg::Sequencer => SEQUENCER_LEDGER_TABLES,
        StorageNodeTypeArg::FullNode => FULL_NODE_LEDGER_TABLES,
        StorageNodeTypeArg::BatchProver => BATCH_PROVER_LEDGER_TABLES,
        StorageNodeTypeArg::LightClient => LIGHT_CLIENT_PROVER_LEDGER_TABLES,
    };

    cfs.iter().map(|x| x.to_string()).collect::<Vec<_>>()
}
