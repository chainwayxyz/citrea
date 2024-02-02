use reth_primitives::TransactionKind;
use reth_primitives::{
    Address, Transaction, TransactionSigned, TransactionSignedEcRecovered, TxHash, B256, U256,
};
use reth_rpc_types::trace::geth::{
    FourByteFrame, GethDebugBuiltInTracerType, GethDebugTracerType, GethDebugTracingOptions,
    GethTrace, NoopFrame,
};
use revm::primitives::db::{Database, DatabaseCommit};
use revm::primitives::{CfgEnv, Env, ResultAndState, TransactTo, TxEnv};
use revm::Inspector;
use revm_inspectors::tracing::{FourByteInspector, TracingInspector, TracingInspectorConfig};

use crate::error::rpc::EthApiError;
use crate::error::rpc::EthResult;
use crate::evm::db::EvmDb;

pub(crate) fn trace_transaction<C: sov_modules_api::Context>(
    opts: GethDebugTracingOptions,
    env: Env,
    db: &mut EvmDb<'_, C>,
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
                    let mut inspector = FourByteInspector::default();
                    let (res, _) = inspect(db, env, &mut inspector)?;
                    return Ok((FourByteFrame::from(inspector).into(), res.state));
                }
                GethDebugBuiltInTracerType::CallTracer => {
                    let call_config = tracer_config
                        .into_call_config()
                        .map_err(|_| EthApiError::InvalidTracerConfig)?;
                    let mut inspector = TracingInspector::new(
                        TracingInspectorConfig::from_geth_config(&config)
                            .set_record_logs(call_config.with_log.unwrap_or_default()),
                    );
                    let (res, _) = inspect(db, env, &mut inspector)?;
                    let frame = inspector
                        .into_geth_builder()
                        .geth_call_traces(call_config, res.result.gas_used());
                    return Ok((frame.into(), res.state));
                }
                GethDebugBuiltInTracerType::PreStateTracer => {
                    // Requires DatabaseRef trait
                    // meaning we need a readonly state to implement this
                    todo!("PreStateTracer")
                }
                GethDebugBuiltInTracerType::NoopTracer => {
                    Ok((NoopFrame::default().into(), Default::default()))
                }
            },
            GethDebugTracerType::JsTracer(_code) => {
                // This also requires DatabaseRef trait
                // Implement after readonly state is implemented
                todo!("JsTracer")
            }
        };
    }

    // default structlog tracer
    let inspector_config = TracingInspectorConfig::from_geth_config(&config);

    let mut inspector = TracingInspector::new(inspector_config);

    let (res, _) = inspect(db, env, &mut inspector)?;
    let gas_used = res.result.gas_used();
    let return_value = res.result.into_output().unwrap_or_default();
    let frame = inspector
        .into_geth_builder()
        .geth_traces(gas_used, return_value, config);

    Ok((frame.into(), res.state))
}

/// Executes the [Env] against the given [Database] without committing state changes.
pub(crate) fn inspect<DB, I>(db: DB, env: Env, inspector: I) -> EthResult<(ResultAndState, Env)>
where
    DB: Database,
    <DB as Database>::Error: Into<EthApiError>,
    I: Inspector<DB>,
{
    let mut evm = revm::EVM::with_env(env);
    evm.database(db);
    let res = evm.inspect(inspector)?;
    Ok((res, evm.env))
}

/// Heavily inspired from:
/// https://github.com/paradigmxyz/reth/blob/606640285e763b64519213bad34c76fe4d24652f/crates/rpc/rpc/src/eth/revm_utils.rs#L176
pub(crate) fn replay_transactions_until<C, I, Tx>(
    db: &mut EvmDb<'_, C>,
    cfg: CfgEnv,
    block_env: revm::primitives::BlockEnv,
    transactions: I,
    target_tx_hash: B256,
) -> EthResult<()>
where
    C: sov_modules_api::Context,
    I: IntoIterator<Item = Tx>,
    Tx: FillableTransaction,
{
    let env = Env {
        cfg,
        block: block_env,
        tx: TxEnv::default(),
    };
    let mut evm = revm::EVM::with_env(env);
    evm.database(db);
    for tx in transactions.into_iter() {
        if tx.hash() == target_tx_hash {
            // reached the target transaction
            break;
        }

        tx.try_fill_tx_env(&mut evm.env.tx)?;
        let res = evm.transact()?;
        evm.db.as_mut().expect("is set").commit(res.state)
    }
    Ok(())
}

/// Taken from reth
/// https://github.com/paradigmxyz/reth/blob/606640285e763b64519213bad34c76fe4d24652f/crates/rpc/rpc/src/eth/revm_utils.rs#L69
/// Helper type to work with different transaction types when configuring the EVM env.
///
/// This makes it easier to handle errors.
pub(crate) trait FillableTransaction {
    /// Returns the hash of the transaction.
    fn hash(&self) -> TxHash;

    /// Fill the transaction environment with the given transaction.
    fn try_fill_tx_env(&self, tx_env: &mut TxEnv) -> EthResult<()>;
}

impl FillableTransaction for TransactionSignedEcRecovered {
    fn hash(&self) -> TxHash {
        self.hash
    }

    fn try_fill_tx_env(&self, tx_env: &mut TxEnv) -> EthResult<()> {
        fill_tx_env_with_recovered(tx_env, self);
        Ok(())
    }
}
impl FillableTransaction for TransactionSigned {
    fn hash(&self) -> TxHash {
        self.hash
    }

    fn try_fill_tx_env(&self, tx_env: &mut TxEnv) -> EthResult<()> {
        let signer = self
            .recover_signer()
            .ok_or_else(|| EthApiError::InvalidTransactionSignature)?;
        fill_tx_env(tx_env, self, signer);
        Ok(())
    }
}

/// Fill transaction environment from [TransactionSignedEcRecovered].
pub fn fill_tx_env_with_recovered(tx_env: &mut TxEnv, transaction: &TransactionSignedEcRecovered) {
    fill_tx_env(tx_env, transaction.as_ref(), transaction.signer());
}

/// Returns a new [TxEnv] filled with the transaction's data.
pub fn tx_env_with_recovered(transaction: &TransactionSignedEcRecovered) -> TxEnv {
    let mut tx_env = TxEnv::default();

    fill_tx_env(&mut tx_env, transaction.as_ref(), transaction.signer());

    tx_env
}

/// Fill transaction environment from a [Transaction] and the given sender address.
pub fn fill_tx_env<T>(tx_env: &mut TxEnv, transaction: T, sender: Address)
where
    T: AsRef<Transaction>,
{
    tx_env.caller = sender;
    match transaction.as_ref() {
        Transaction::Legacy(tx) => {
            tx_env.gas_limit = tx.gas_limit;
            tx_env.gas_price = U256::from(tx.gas_price);
            tx_env.gas_priority_fee = None;
            tx_env.transact_to = match tx.to {
                TransactionKind::Call(to) => TransactTo::Call(to),
                TransactionKind::Create => TransactTo::create(),
            };
            tx_env.value = tx.value.into();
            tx_env.data = tx.input.clone();
            tx_env.chain_id = tx.chain_id;
            tx_env.nonce = Some(tx.nonce);
            tx_env.access_list.clear();
            tx_env.blob_hashes.clear();
            tx_env.max_fee_per_blob_gas.take();
        }
        Transaction::Eip2930(tx) => {
            tx_env.gas_limit = tx.gas_limit;
            tx_env.gas_price = U256::from(tx.gas_price);
            tx_env.gas_priority_fee = None;
            tx_env.transact_to = match tx.to {
                TransactionKind::Call(to) => TransactTo::Call(to),
                TransactionKind::Create => TransactTo::create(),
            };
            tx_env.value = tx.value.into();
            tx_env.data = tx.input.clone();
            tx_env.chain_id = Some(tx.chain_id);
            tx_env.nonce = Some(tx.nonce);
            tx_env.access_list = tx
                .access_list
                .0
                .iter()
                .map(|l| {
                    (
                        l.address,
                        l.storage_keys
                            .iter()
                            .map(|k| U256::from_be_bytes(k.0))
                            .collect(),
                    )
                })
                .collect();
            tx_env.blob_hashes.clear();
            tx_env.max_fee_per_blob_gas.take();
        }
        Transaction::Eip1559(tx) => {
            tx_env.gas_limit = tx.gas_limit;
            tx_env.gas_price = U256::from(tx.max_fee_per_gas);
            tx_env.gas_priority_fee = Some(U256::from(tx.max_priority_fee_per_gas));
            tx_env.transact_to = match tx.to {
                TransactionKind::Call(to) => TransactTo::Call(to),
                TransactionKind::Create => TransactTo::create(),
            };
            tx_env.value = tx.value.into();
            tx_env.data = tx.input.clone();
            tx_env.chain_id = Some(tx.chain_id);
            tx_env.nonce = Some(tx.nonce);
            tx_env.access_list = tx
                .access_list
                .0
                .iter()
                .map(|l| {
                    (
                        l.address,
                        l.storage_keys
                            .iter()
                            .map(|k| U256::from_be_bytes(k.0))
                            .collect(),
                    )
                })
                .collect();
            tx_env.blob_hashes.clear();
            tx_env.max_fee_per_blob_gas.take();
        }
        Transaction::Eip4844(tx) => {
            tx_env.gas_limit = tx.gas_limit;
            tx_env.gas_price = U256::from(tx.max_fee_per_gas);
            tx_env.gas_priority_fee = Some(U256::from(tx.max_priority_fee_per_gas));
            tx_env.transact_to = match tx.to {
                TransactionKind::Call(to) => TransactTo::Call(to),
                TransactionKind::Create => TransactTo::create(),
            };
            tx_env.value = tx.value.into();
            tx_env.data = tx.input.clone();
            tx_env.chain_id = Some(tx.chain_id);
            tx_env.nonce = Some(tx.nonce);
            tx_env.access_list = tx
                .access_list
                .0
                .iter()
                .map(|l| {
                    (
                        l.address,
                        l.storage_keys
                            .iter()
                            .map(|k| U256::from_be_bytes(k.0))
                            .collect(),
                    )
                })
                .collect();
            tx_env.blob_hashes = tx.blob_versioned_hashes.clone();
            tx_env.max_fee_per_blob_gas = Some(U256::from(tx.max_fee_per_blob_gas));
        }
    }
}
