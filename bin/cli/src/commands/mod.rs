pub(crate) use backup::*;
use citrea_common::NodeType;
use clap::ValueEnum;
use derive_more::Display;
pub(crate) use prune::*;
pub(crate) use rollback::*;
use sov_db::schema::tables::{
    BATCH_PROVER_LEDGER_TABLES, FULL_NODE_LEDGER_TABLES, LIGHT_CLIENT_PROVER_LEDGER_TABLES,
    SEQUENCER_LEDGER_TABLES,
};

mod backup;
mod prune;
mod rollback;

#[derive(Copy, Clone, Display, ValueEnum)]
pub enum NodeTypeArg {
    Sequencer,
    FullNode,
    BatchProver,
    LightClientProver,
}

impl From<NodeTypeArg> for NodeType {
    fn from(value: NodeTypeArg) -> Self {
        match value {
            NodeTypeArg::Sequencer => NodeType::Sequencer,
            NodeTypeArg::FullNode => NodeType::FullNode,
            NodeTypeArg::BatchProver => NodeType::BatchProver,
            NodeTypeArg::LightClientProver => NodeType::LightClientProver,
        }
    }
}

pub(crate) fn cfs_from_node_type(node_type: NodeTypeArg) -> Vec<String> {
    let cfs = match node_type {
        NodeTypeArg::Sequencer => SEQUENCER_LEDGER_TABLES,
        NodeTypeArg::FullNode => FULL_NODE_LEDGER_TABLES,
        NodeTypeArg::BatchProver => BATCH_PROVER_LEDGER_TABLES,
        NodeTypeArg::LightClientProver => LIGHT_CLIENT_PROVER_LEDGER_TABLES,
    };

    cfs.iter().map(|x| x.to_string()).collect::<Vec<_>>()
}
