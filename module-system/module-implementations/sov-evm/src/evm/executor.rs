use std::convert::Infallible;

use reth_primitives::TransactionSignedEcRecovered;
use reth_revm::tracing::{TracingInspector, TracingInspectorConfig};
use revm::primitives::{
    CfgEnv, EVMError, Env, ExecutionResult, InvalidTransaction, ResultAndState, TxEnv,
};
use revm::{self, Database, DatabaseCommit};

use super::conversions::create_tx_env;
use super::primitive_types::BlockEnv;

#[allow(dead_code)]
pub(crate) fn execute_tx<DB: Database<Error = Infallible> + DatabaseCommit>(
    db: DB,
    block_env: &BlockEnv,
    tx: &TransactionSignedEcRecovered,
    config_env: CfgEnv,
) -> Result<ExecutionResult, EVMError<Infallible>> {
    let env = Box::new(Env {
        block: block_env.into(),
        cfg: config_env,
        tx: create_tx_env(tx),
    });

    let mut evm = revm::Evm::builder().with_db(db).with_env(env).build();
    evm.transact_commit()
}

pub(crate) fn execute_multiple_tx<DB: Database<Error = Infallible> + DatabaseCommit>(
    db: DB,
    block_env: &BlockEnv,
    txs: &[TransactionSignedEcRecovered],
    config_env: CfgEnv,
) -> Vec<Result<ExecutionResult, EVMError<Infallible>>> {
    if txs.is_empty() {
        return vec![];
    }

    let block_gas_limit = block_env.gas_limit;
    let mut cumulative_gas_used = 0u64;

    let env = Box::new(Env {
        block: block_env.into(),
        cfg: config_env,
        tx: TxEnv::default(),
    });
    let mut evm = revm::Evm::builder().with_db(db).with_env(env).build();

    let mut tx_results = Vec::with_capacity(txs.len());
    for tx in txs {
        let block_available_gas = block_gas_limit - cumulative_gas_used;
        let result = if tx.transaction.gas_limit() > block_available_gas {
            Err(EVMError::Transaction(
                InvalidTransaction::CallerGasLimitMoreThanBlock,
            ))
        } else {
            evm = evm
                .modify()
                .modify_env(|env| {
                    env.tx = create_tx_env(tx);
                })
                .build();
            evm.transact_commit()
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
    config_env: CfgEnv,
) -> Result<ResultAndState, EVMError<Infallible>> {
    let env = Env {
        cfg: config_env,
        block: block_env.into(),
        tx,
    };

    let config = TracingInspectorConfig::all();

    let mut evm = revm::Evm::builder()
        .with_db(db)
        .with_external_context(TracingInspector::new(config))
        .with_env(Box::new(env))
        .build();

    evm.transact()
}
