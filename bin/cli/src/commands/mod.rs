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
pub enum CliNodeTypeArg {
    Sequencer,
    FullNode,
    BatchProver,
    LightClientProver,
}

impl From<CliNodeTypeArg> for NodeType {
    fn from(value: CliNodeTypeArg) -> Self {
        match value {
            CliNodeTypeArg::Sequencer => NodeType::Sequencer,
            CliNodeTypeArg::FullNode => NodeType::FullNode,
            CliNodeTypeArg::BatchProver => NodeType::BatchProver,
            CliNodeTypeArg::LightClientProver => NodeType::LightClientProver,
        }
    }
}

pub(crate) fn cfs_from_node_type(node_type: CliNodeTypeArg) -> Vec<String> {
    let cfs = match node_type {
        CliNodeTypeArg::Sequencer => SEQUENCER_LEDGER_TABLES,
        CliNodeTypeArg::FullNode => FULL_NODE_LEDGER_TABLES,
        CliNodeTypeArg::BatchProver => BATCH_PROVER_LEDGER_TABLES,
        CliNodeTypeArg::LightClientProver => LIGHT_CLIENT_PROVER_LEDGER_TABLES,
    };

    cfs.iter().map(|x| x.to_string()).collect::<Vec<_>>()
}
