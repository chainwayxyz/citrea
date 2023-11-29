use std::convert::Infallible;

use reth_primitives::TransactionSignedEcRecovered;
use reth_revm::tracing::{TracingInspector, TracingInspectorConfig};
use revm::primitives::{CfgEnv, EVMError, Env, ExecutionResult, ResultAndState, TxEnv};
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
    txs: &Vec<TransactionSignedEcRecovered>,
    config_env: CfgEnv,
) -> Vec<Result<ExecutionResult, EVMError<Infallible>>> {
    let mut evm = revm::new();

    evm.env.block = block_env.into();
    evm.env.cfg = config_env;
    evm.database(db);

    txs.into_iter()
        .map(|tx| {
            evm.env.tx = create_tx_env(tx);
            evm.transact_commit()
        })
        .collect()
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
