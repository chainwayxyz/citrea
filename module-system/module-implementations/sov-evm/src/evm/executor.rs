use std::convert::Infallible;

use reth_interfaces::executor::{BlockExecutionError, BlockValidationError};
use reth_primitives::TransactionSignedEcRecovered;
use reth_revm::tracing::{TracingInspector, TracingInspectorConfig};
use revm::primitives::{CfgEnv, EVMError, Env, ExecutionResult, ResultAndState, TxEnv};
use revm::{self, Database, DatabaseCommit};
use tracing::trace;

use super::conversions::create_tx_env;
use super::primitive_types::BlockEnv;

#[allow(dead_code)]
pub(crate) fn execute_tx<DB: Database<Error = Infallible> + DatabaseCommit>(
    db: DB,
    block_env: &BlockEnv,
    tx: &TransactionSignedEcRecovered,
    config_env: CfgEnv,
) -> Result<ExecutionResult, EVMError<Infallible>> {
    let mut evm = revm::new();

    let env = Env {
        block: block_env.into(),
        cfg: config_env,
        tx: create_tx_env(tx),
    };

    evm.env = env;
    evm.database(db);
    evm.transact_commit()
}

pub(crate) fn execute_multiple_tx<DB: Database<Error = Infallible> + DatabaseCommit>(
    db: DB,
    block_env: &BlockEnv,
    txs: &[TransactionSignedEcRecovered],
    config_env: CfgEnv,
) -> Result<Vec<Result<ExecutionResult, EVMError<Infallible>>>, BlockExecutionError> {
    if txs.is_empty() {
        return Ok(vec![]);
    }

    let block_gas_limit = block_env.gas_limit;
    let mut cumulative_gas_used = 0u64;

    let mut evm = revm::new();
    evm.env.block = block_env.into();
    evm.env.cfg = config_env;
    evm.database(db);

    let mut tx_results = Vec::with_capacity(txs.len());
    for tx in txs {
        let block_available_gas = block_gas_limit - cumulative_gas_used;
        if tx.transaction.gas_limit() > block_available_gas {
            return Err(
                BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas {
                    transaction_gas_limit: tx.transaction.gas_limit(),
                    block_available_gas,
                }
                .into(),
            );
        }
        evm.env.tx = create_tx_env(tx);
        let result = evm.transact_commit();
        cumulative_gas_used += result.as_ref().map(|r| r.gas_used()).unwrap_or(0);
        tx_results.push(result);
    }
    Ok(tx_results)
}

pub(crate) fn inspect<DB: Database<Error = Infallible> + DatabaseCommit>(
    db: DB,
    block_env: &BlockEnv,
    tx: TxEnv,
    config_env: CfgEnv,
) -> Result<ResultAndState, EVMError<Infallible>> {
    let mut evm = revm::new();

    let env = Env {
        cfg: config_env,
        block: block_env.into(),
        tx,
    };

    evm.env = env;
    evm.database(db);

    let config = TracingInspectorConfig::all();

    let mut inspector = TracingInspector::new(config);

    evm.inspect(&mut inspector)
}
