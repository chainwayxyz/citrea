use std::convert::Infallible;

use reth_revm::tracing::{TracingInspector, TracingInspectorConfig};
use revm::primitives::{CfgEnvWithHandlerCfg, EVMError, ResultAndState, TxEnv};
use revm::{self, inspector_handle_register, Database, DatabaseCommit};

use super::primitive_types::BlockEnv;

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
