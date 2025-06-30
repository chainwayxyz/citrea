use std::collections::HashMap;

pub type Result = anyhow::Result<RollbackResult>;

#[derive(Default)]
pub struct RollbackResult {
    pub(crate) processed_tables: HashMap<&'static str, u32>,
}

pub struct RollbackContext {
    pub(crate) l2_target: Option<u64>,
    pub(crate) l1_target: Option<u64>,
    pub(crate) last_sequencer_commitment_index: Option<u32>,
}

pub trait LedgerNodeRollback {
    fn execute(&self, context: RollbackContext) -> Result;
}
