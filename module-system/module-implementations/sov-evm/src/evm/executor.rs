use std::convert::Infallible;

use reth_primitives::TransactionSignedEcRecovered;
use reth_revm::tracing::{TracingInspector, TracingInspectorConfig};
use revm::primitives::{
    CfgEnvWithHandlerCfg, EVMError, Env, ExecutionResult, InvalidTransaction, ResultAndState, TxEnv,
};
use revm::{self, inspector_handle_register, Context, Database, DatabaseCommit, EvmContext};

use super::conversions::create_tx_env;
use super::handler::{citrea_handler, CitreaHandlerContext};
use super::primitive_types::BlockEnv;

struct CitreaEvm<'a, EXT, DB: Database> {
    evm: revm::Evm<'a, EXT, DB>,
}

impl<'a, EXT, DB> CitreaEvm<'a, EXT, DB>
where
    DB: Database<Error = Infallible> + DatabaseCommit,
    EXT: CitreaHandlerContext,
{
    /// Creates a new Citrea EVM with the given parameters.
    fn new(db: DB, block_env: &BlockEnv, config_env: CfgEnvWithHandlerCfg, ext: EXT) -> Self {
        let evm_env = Env::boxed(config_env.cfg_env, block_env.into(), Default::default());
        let evm_context = EvmContext::new_with_env(db, evm_env);
        let context = Context::new(evm_context, ext);
        let handler = citrea_handler(config_env.handler_cfg);
        let evm = revm::Evm::new(context, handler);
        Self { evm }
    }

    /// Sets all required parameters and executes a transaction.
    fn transact_commit(
        &mut self,
        tx: &TransactionSignedEcRecovered,
    ) -> Result<ExecutionResult, EVMError<Infallible>> {
        self.evm.context.external.set_current_tx_hash(tx.hash());
        *self.evm.tx_mut() = create_tx_env(tx);
        self.evm.transact_commit()
    }
}

#[allow(dead_code)]
pub(crate) fn execute_tx<
    DB: Database<Error = Infallible> + DatabaseCommit,
    EXT: CitreaHandlerContext,
>(
    db: DB,
    block_env: &BlockEnv,
    tx: &TransactionSignedEcRecovered,
    config_env: CfgEnvWithHandlerCfg,
    ext: &mut EXT,
) -> Result<ExecutionResult, EVMError<Infallible>> {
    let mut evm = CitreaEvm::new(db, block_env, config_env, ext);
    evm.transact_commit(tx)
}

pub(crate) fn execute_multiple_tx<
    DB: Database<Error = Infallible> + DatabaseCommit,
    EXT: CitreaHandlerContext,
>(
    db: DB,
    block_env: &BlockEnv,
    txs: &[TransactionSignedEcRecovered],
    config_env: CfgEnvWithHandlerCfg,
    ext: &mut EXT,
) -> Vec<Result<ExecutionResult, EVMError<Infallible>>> {
    if txs.is_empty() {
        return vec![];
    }

    let mut evm = CitreaEvm::new(db, block_env, config_env, ext);

    let block_gas_limit = block_env.gas_limit;
    let mut cumulative_gas_used = 0u64;

    let mut tx_results = Vec::with_capacity(txs.len());
    for tx in txs {
        let block_available_gas = block_gas_limit - cumulative_gas_used;
        let result = if tx.transaction.gas_limit() > block_available_gas {
            Err(EVMError::Transaction(
                InvalidTransaction::CallerGasLimitMoreThanBlock,
            ))
        } else {
            evm.transact_commit(tx)
        };
        cumulative_gas_used += result.as_ref().map(|r| r.gas_used()).unwrap_or(0);
        tx_results.push(result);
    }
    tx_results
}

pub(crate) fn inspect<DB: Database<Error = Infallible> + DatabaseCommit>(
    db: DB,
    block_env: &BlockEnv,
    tx: TxEnv,
    config_env: CfgEnvWithHandlerCfg,
) -> Result<ResultAndState, EVMError<Infallible>> {
    let config = TracingInspectorConfig::all();

    let mut evm = revm::Evm::builder()
        .with_db(db)
        .with_external_context(TracingInspector::new(config))
        .with_cfg_env_with_handler_cfg(config_env)
        .with_block_env(block_env.into())
        .with_tx_env(tx)
        .append_handler_register(inspector_handle_register)
        .build();

    evm.transact()
}
