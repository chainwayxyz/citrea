use std::convert::Infallible;

use reth_primitives::TransactionSignedEcRecovered;
use revm::primitives::{CfgEnvWithHandlerCfg, EVMError, Env, ExecutionResult, InvalidTransaction};
use revm::{self, Context, Database, DatabaseCommit, EvmContext};

use super::conversions::create_tx_env;
use super::handler::{citrea_handler, CitreaExternalExt};
use super::primitive_types::BlockEnv;
use crate::SYSTEM_SIGNER;

struct CitreaEvm<'a, EXT, DB: Database> {
    evm: revm::Evm<'a, EXT, DB>,
}

impl<'a, EXT, DB> CitreaEvm<'a, EXT, DB>
where
    DB: Database<Error = Infallible> + DatabaseCommit,
    EXT: CitreaExternalExt,
{
    /// Creates a new Citrea EVM with the given parameters.
    fn new(db: DB, block_env: BlockEnv, config_env: CfgEnvWithHandlerCfg, ext: EXT) -> Self {
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
    EXT: CitreaExternalExt,
>(
    db: DB,
    block_env: BlockEnv,
    tx: &TransactionSignedEcRecovered,
    config_env: CfgEnvWithHandlerCfg,
    ext: &mut EXT,
) -> Result<ExecutionResult, EVMError<Infallible>> {
    let mut evm = CitreaEvm::new(db, block_env, config_env, ext);
    evm.transact_commit(tx)
}

pub(crate) fn execute_multiple_tx<
    DB: Database<Error = Infallible> + DatabaseCommit,
    EXT: CitreaExternalExt,
>(
    db: DB,
    block_env: BlockEnv,
    txs: &[TransactionSignedEcRecovered],
    config_env: CfgEnvWithHandlerCfg,
    ext: &mut EXT,
    prev_gas_used: u64,
) -> Vec<Result<ExecutionResult, EVMError<Infallible>>> {
    if txs.is_empty() {
        return vec![];
    }

    let block_gas_limit = block_env.gas_limit;
    let mut cumulative_gas_used = prev_gas_used;

    let mut evm = CitreaEvm::new(db, block_env, config_env, ext);

    let mut tx_results = Vec::with_capacity(txs.len());
    for tx in txs {
        let block_available_gas = block_gas_limit - cumulative_gas_used;
        let result = if tx.transaction.gas_limit() > block_available_gas {
            Err(EVMError::Transaction(
                InvalidTransaction::CallerGasLimitMoreThanBlock,
            ))
        } else if tx.signer() == SYSTEM_SIGNER {
            Err(EVMError::Custom(format!(
                "Ignored system transaction: {:?}",
                hex::encode(tx.hash())
            )))
        } else {
            evm.transact_commit(tx)
        };
        cumulative_gas_used += result.as_ref().map(|r| r.gas_used()).unwrap_or(0);
        tx_results.push(result);
    }
    tx_results
}

pub(crate) fn execute_system_txs<
    DB: Database<Error = Infallible> + DatabaseCommit,
    EXT: CitreaExternalExt,
>(
    db: DB,
    block_env: BlockEnv,
    system_txs: &[TransactionSignedEcRecovered],
    config_env: CfgEnvWithHandlerCfg,
    ext: &mut EXT,
) -> Vec<ExecutionResult> {
    let mut evm = CitreaEvm::new(db, block_env, config_env, ext);

    let mut tx_results = vec![];
    for tx in system_txs {
        let result = evm
            .transact_commit(tx)
            .expect("System transactions must never fail");
        tx_results.push(result);
    }
    tx_results
}
