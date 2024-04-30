use std::convert::Infallible;

use reth_primitives::TransactionSignedEcRecovered;
use revm::primitives::{
    CfgEnvWithHandlerCfg, EVMError, Env, ExecutionResult, ResultAndState, State,
};
use revm::{self, Context, Database, DatabaseCommit, EvmContext};

use super::conversions::create_tx_env;
use super::handler::{citrea_handler, CitreaExternalExt};
use super::primitive_types::BlockEnv;
use crate::SYSTEM_SIGNER;

pub(crate) struct CitreaEvm<'a, EXT, DB: Database> {
    evm: revm::Evm<'a, EXT, DB>,
}

impl<'a, EXT, DB> CitreaEvm<'a, EXT, DB>
where
    DB: Database,
    EXT: CitreaExternalExt,
{
    /// Creates a new Citrea EVM with the given parameters.
    pub fn new(db: DB, block_env: BlockEnv, config_env: CfgEnvWithHandlerCfg, ext: EXT) -> Self {
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
    ) -> Result<ExecutionResult, EVMError<DB::Error>>
    where
        DB: DatabaseCommit,
    {
        self.evm.context.external.set_current_tx_hash(tx.hash());
        *self.evm.tx_mut() = create_tx_env(tx);
        self.evm.transact_commit()
    }

    /// Runs a single transaction in the configured environment and proceeds
    /// to return the result and state diff (without applying it).
    fn transact(
        &mut self,
        tx: &TransactionSignedEcRecovered,
    ) -> Result<ResultAndState, EVMError<Infallible>> {
        self.evm.context.external.set_current_tx_hash(tx.hash());
        *self.evm.tx_mut() = create_tx_env(tx);
        self.evm.transact()
    }

    /// Commits the given state diff to the database.
    fn commit(&mut self, state: State) {
        self.evm.context.evm.db.commit(state)
    }
}

#[allow(dead_code)]
pub(crate) fn execute_tx<DB: Database + DatabaseCommit, EXT: CitreaExternalExt>(
    db: DB,
    block_env: BlockEnv,
    tx: &TransactionSignedEcRecovered,
    config_env: CfgEnvWithHandlerCfg,
    ext: &mut EXT,
) -> Result<ExecutionResult, EVMError<DB::Error>> {
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
        let result_and_state = match evm.transact(tx) {
            Ok(result_and_state) => result_and_state,
            Err(e) => {
                tx_results.push(Err(e));
                continue;
            }
        };

        // Check if the transaction used more gas than the available block gas limit
        let result = if cumulative_gas_used + result_and_state.result.gas_used() > block_gas_limit {
            Err(EVMError::Custom(format!(
                "Gas used exceeds block gas limit {:?}",
                block_gas_limit
            )))
        } else if tx.signer() == SYSTEM_SIGNER {
            Err(EVMError::Custom(format!(
                "Invalid system transaction: {:?}",
                hex::encode(tx.hash())
            )))
        } else {
            evm.commit(result_and_state.state);
            cumulative_gas_used += result_and_state.result.gas_used();
            Ok(result_and_state.result)
        };
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
