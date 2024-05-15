use reth_primitives::revm_primitives::TxEnv;
use reth_primitives::{TransactionSigned, TransactionSignedEcRecovered, TxHash, U256};
use reth_rpc::eth::error::{EthApiError, EthResult, RpcInvalidTransactionError};
use reth_rpc_types::trace::geth::{
    FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions,
    GethTrace, NoopFrame,
};
use revm::precompile::{PrecompileSpecId, Precompiles};
use revm::primitives::db::Database;
use revm::primitives::{Address, CfgEnvWithHandlerCfg, EVMError, ResultAndState, SpecId};
use revm::{inspector_handle_register, Inspector};
use revm_inspectors::tracing::{FourByteInspector, TracingInspector, TracingInspectorConfig};

use crate::evm::db::EvmDb;
use crate::evm::primitive_types::BlockEnv;
use crate::handler::{
    citrea_handle_register, CitreaExternal, CitreaExternalExt, TracingCitreaExternal, TxInfo,
};

pub(crate) fn trace_transaction<C: sov_modules_api::Context>(
    opts: GethDebugTracingOptions,
    config_env: CfgEnvWithHandlerCfg,
    block_env: BlockEnv,
    tx_env: TxEnv,
    tx_hash: TxHash,
    db: &mut EvmDb<'_, C>,
    l1_fee_rate: u128,
) -> EthResult<(GethTrace, revm::primitives::State)> {
    let GethDebugTracingOptions {
        config,
        tracer,
        tracer_config,
        ..
    } = opts;

    if let Some(tracer) = tracer {
        return match tracer {
            GethDebugTracerType::BuiltInTracer(tracer) => match tracer {
                GethDebugBuiltInTracerType::FourByteTracer => {
                    let inspector = FourByteInspector::default();
                    let mut citrea_inspector = TracingCitreaExternal::new(inspector, l1_fee_rate);
                    let res = inspect_citrea(
                        db,
                        config_env,
                        block_env,
                        tx_env,
                        tx_hash,
                        &mut citrea_inspector,
                    )?;
                    return Ok((
                        FourByteFrame::from(citrea_inspector.inspector).into(),
                        res.state,
                    ));
                }
                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config
                        .into_call_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;
                    let inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_config(&config)
                            .set_record_logs(call_config.with_log.unwrap_or_default()),
                    );
                    let mut citrea_inspector = TracingCitreaExternal::new(inspector, l1_fee_rate);
                    let res = inspect_citrea(
                        db,
                        config_env,
                        block_env,
                        tx_env,
                        tx_hash,
                        &mut citrea_inspector,
                    )?;
                    let frame = citrea_inspector
                        .inspector
                        .into_geth_builder()
                        .geth_call_traces(call_config, res.result.gas_used());
                    return Ok((frame.into(), res.state));
                }
                GethDebugBuiltInTracerType::PreStateTracer => {
                    // Requires DatabaseRef trait
                    // meaning we need a readonly state to implement this
                    return Err(EthApiError::Unsupported("PreStateTracer"));
                }
                GethDebugBuiltInTracerType::NoopTracer => {
                    Ok((NoopFrame::default().into(), Default::default()))
                }
                // TODO: either implement or return unsupported
                GethDebugBuiltInTracerType::MuxTracer => todo!("MuxTracer"),
            },
            GethDebugTracerType::JsTracer(_code) => {
                // This also requires DatabaseRef trait
                // Implement after readonly state is implemented
                return Err(EthApiError::Unsupported("JsTracer"));
            }
        };
    }

    // default structlog tracer
    let inspector_config = TracingInspectorConfig::from_geth_config(&config);

    let inspector = TracingInspector::new(inspector_config);
    let mut citrea_inspector = TracingCitreaExternal::new(inspector, l1_fee_rate);

    let res = inspect_citrea(
        db,
        config_env,
        block_env,
        tx_env,
        tx_hash,
        &mut citrea_inspector,
    )?;
    let gas_used = res.result.gas_used();
    let return_value = res.result.into_output().unwrap_or_default();
    let frame =
        citrea_inspector
            .inspector
            .into_geth_builder()
            .geth_traces(gas_used, return_value, config);

    Ok((frame.into(), res.state))
}

/// Executes the [Env] against the given [Database] without committing state changes.
fn inspect_citrea<DB, I>(
    db: DB,
    config_env: CfgEnvWithHandlerCfg,
    block_env: BlockEnv,
    tx_env: TxEnv,
    tx_hash: TxHash,
    inspector: I,
) -> Result<ResultAndState, EVMError<DB::Error>>
where
    DB: Database,
    <DB as Database>::Error: Into<EthApiError>,
    I: Inspector<DB>,
    I: CitreaExternalExt,
{
    let mut evm = revm::Evm::builder()
        .with_db(db)
        .with_external_context(inspector)
        .with_cfg_env_with_handler_cfg(config_env)
        .with_block_env(block_env.into())
        .with_tx_env(tx_env)
        .append_handler_register(citrea_handle_register)
        .append_handler_register(inspector_handle_register)
        .build();
    evm.context.external.set_current_tx_hash(tx_hash);

    evm.transact()
}

/// Executes the [Env] against the given [Database] without committing state changes.
pub(crate) fn inspect<DB, I>(
    db: DB,
    config_env: CfgEnvWithHandlerCfg,
    block_env: BlockEnv,
    tx_env: TxEnv,
    inspector: I,
) -> Result<ResultAndState, EVMError<DB::Error>>
where
    DB: Database,
    <DB as Database>::Error: Into<EthApiError>,
    I: Inspector<DB>,
{
    let mut evm = revm::Evm::builder()
        .with_db(db)
        .with_external_context(inspector)
        .with_cfg_env_with_handler_cfg(config_env)
        .with_block_env(block_env.into())
        .with_tx_env(tx_env)
        .append_handler_register(inspector_handle_register)
        .build();

    evm.transact()
}

pub(crate) fn inspect_no_tracing<DB>(
    db: DB,
    config_env: CfgEnvWithHandlerCfg,
    block_env: BlockEnv,
    tx_env: TxEnv,
    l1_fee_rate: u128,
) -> Result<(ResultAndState, TxInfo), EVMError<DB::Error>>
where
    DB: Database,
{
    let tmp_hash: TxHash = b"hash_of_an_ephemeral_transaction".into();
    let mut ext = CitreaExternal::new(l1_fee_rate);
    ext.set_current_tx_hash(tmp_hash);

    let mut evm = revm::Evm::builder()
        .with_db(db)
        .with_external_context(&mut ext)
        .with_cfg_env_with_handler_cfg(config_env)
        .with_block_env(block_env.into())
        .with_tx_env(tx_env)
        .append_handler_register(citrea_handle_register)
        .build();

    let result_and_state = evm.transact()?;
    let tx_info = evm
        .context
        .external
        .get_tx_info(tmp_hash)
        .unwrap_or_default(); // default 0 in case tx was unsuccessful
    Ok((result_and_state, tx_info))
}

/// Taken from reth
/// https://github.com/paradigmxyz/reth/blob/606640285e763b64519213bad34c76fe4d24652f/crates/rpc/rpc/src/eth/revm_utils.rs#L69
/// Helper type to work with different transaction types when configuring the EVM env.
///
/// This makes it easier to handle errors.
pub(crate) trait FillableTransaction {
    /// Returns the hash of the transaction.
    fn hash(&self) -> TxHash;
}

impl FillableTransaction for TransactionSignedEcRecovered {
    fn hash(&self) -> TxHash {
        self.hash
    }
}

impl FillableTransaction for TransactionSigned {
    fn hash(&self) -> TxHash {
        self.hash
    }
}

/// https://github.com/paradigmxyz/reth/blob/332e412a0f8d34ff2bbb7e07921f8cacdcf69d64/crates/rpc/rpc/src/eth/revm_utils.rs#L403
/// Calculates the caller gas allowance.
///
/// `allowance = (account.balance - tx.value) / tx.gas_price`
///
/// Returns an error if the caller has insufficient funds.
/// Caution: This assumes non-zero `env.gas_price`. Otherwise, zero allowance will be returned.
pub(crate) fn caller_gas_allowance(balance: U256, value: U256, gas_price: U256) -> EthResult<U256> {
    Ok(balance
        // Subtract transferred value from the caller balance.
        .checked_sub(value)
        // Return error if the caller has insufficient funds.
        .ok_or_else(|| RpcInvalidTransactionError::InsufficientFunds)?
        // Calculate the amount of gas the caller can afford with the specified gas price.
        .checked_div(gas_price)
        // This will be 0 if gas price is 0. It is fine, because we check it before.
        .unwrap_or_default())
}

/// Returns the addresses of the precompiles corresponding to the SpecId.
#[inline]
pub(crate) fn get_precompiles(spec_id: SpecId) -> impl IntoIterator<Item = Address> {
    let spec = PrecompileSpecId::from_spec_id(spec_id);
    Precompiles::new(spec)
        .addresses()
        .copied()
        .map(Address::from)
}
