use std::sync::Arc;

///! Implements functionality for ef-tests support.
use reth_interfaces::executor::BlockExecutionError;
use reth_primitives::ChainSpec;
use reth_provider::{ExecutorFactory, PrunableBlockExecutor, StateProvider};
use revm::{Database, DatabaseCommit};

use crate::handler::CitreaExternalExt;
use crate::EvmConfig;

/// Processor Factory
pub struct EvmProcessorFactory {
    chain_spec: Arc<ChainSpec>,
    evm_config: EvmConfig,
}

impl EvmProcessorFactory {
    /// New instance
    pub fn new(chain_spec: Arc<ChainSpec>, evm_config: EvmConfig) -> Self {
        Self {
            chain_spec,
            evm_config,
        }
    }
}

impl ExecutorFactory for EvmProcessorFactory {
    fn with_state<'b, SP: StateProvider + 'b>(
        &'b self,
        sp: SP,
    ) -> Box<dyn PrunableBlockExecutor<Error = BlockExecutionError> + 'b> {
        todo!()
    }
}
