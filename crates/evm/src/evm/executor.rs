use reth_primitives::TransactionSignedEcRecovered;
use revm::primitives::{
    BlockEnv, CfgEnvWithHandlerCfg, EVMError, Env, EvmState, ExecutionResult, ResultAndState,
};
use revm::{self, Context, Database, DatabaseCommit, EvmContext};
use short_header_proof_provider::{ShortHeaderProofProviderError, SHORT_HEADER_PROOF_PROVIDER};
use sov_modules_api::{
    native_error, native_trace, SoftConfirmationModuleCallError, SpecId as CitreaSpecId,
};
#[cfg(feature = "native")]
use tracing::trace_span;

use super::conversions::create_tx_env;
use super::handler::{citrea_handler, CitreaExternalExt};
use crate::{EvmDb, SYSTEM_SIGNER};

pub(crate) struct CitreaEvm<'a, EXT, DB: Database> {
    evm: revm::Evm<'a, EXT, DB>,
}

impl<'a, EXT, DB> CitreaEvm<'a, EXT, DB>
where
    DB: Database,
    EXT: CitreaExternalExt,
{
    /// Creates a new Citrea EVM with the given parameters.
    pub fn new(
        db: DB,
        citrea_spec: CitreaSpecId,
        block_env: BlockEnv,
        config_env: CfgEnvWithHandlerCfg,
        ext: EXT,
    ) -> Self {
        let evm_env = Env::boxed(config_env.cfg_env, block_env, Default::default());
        let evm_context = EvmContext::new_with_env(db, evm_env);
        let context = Context::new(evm_context, ext);
        let handler = citrea_handler(citrea_spec, config_env.handler_cfg);
        let evm = revm::Evm::new(context, handler);
        Self { evm }
    }

    /// Sets all required parameters and executes a transaction.
    pub(crate) fn transact_commit(
        &mut self,
        tx: &TransactionSignedEcRecovered,
    ) -> Result<ExecutionResult, EVMError<DB::Error>>
    where
        DB: DatabaseCommit,
    {
        self.evm.context.external.set_current_tx_hash(tx.hash());
        *self.evm.tx_mut() = create_tx_env(tx, self.evm.spec_id());
        self.evm.transact_commit()
    }

    /// Runs a single transaction in the configured environment and proceeds
    /// to return the result and state diff (without applying it).
    fn transact(
        &mut self,
        tx: &TransactionSignedEcRecovered,
    ) -> Result<ResultAndState, EVMError<DB::Error>> {
        self.evm.context.external.set_current_tx_hash(tx.hash());
        *self.evm.tx_mut() = create_tx_env(tx, self.evm.spec_id());
        self.evm.transact()
    }

    /// Commits the given state diff to the database.
    fn commit(&mut self, state: EvmState)
    where
        DB: DatabaseCommit,
    {
        self.evm.context.evm.db.commit(state)
    }
}

/// Will fail on the first error.
/// Rendering the soft confirmation invalid
pub(crate) fn execute_multiple_tx<C: sov_modules_api::Context, EXT: CitreaExternalExt>(
    db: EvmDb<C>,
    block_env: BlockEnv,
    txs: &[TransactionSignedEcRecovered],
    config_env: CfgEnvWithHandlerCfg,
    ext: &mut EXT,
    prev_gas_used: u64,
) -> Result<Vec<ExecutionResult>, SoftConfirmationModuleCallError> {
    if txs.is_empty() {
        return Ok(vec![]);
    }

    let block_gas_limit: u64 = block_env.gas_limit.saturating_to();

    let mut cumulative_gas_used = prev_gas_used;

    let citrea_spec = db.citrea_spec;
    let mut evm = CitreaEvm::new(db, citrea_spec, block_env, config_env, ext);

    let mut tx_results = Vec::with_capacity(txs.len());
    for (_i, tx) in txs.iter().enumerate() {
        #[cfg(feature = "native")]
        let _span =
            trace_span!("Processing tx", i = _i, signer = %tx.signer(), tx_hash = %tx.hash())
                .entered();

        if tx.signer() == SYSTEM_SIGNER {
            let shp_provider = SHORT_HEADER_PROOF_PROVIDER
                .get()
                .expect("Short header proof provider not set");
            // TODO: Check if this is the set_block_info tx, if so:
            // TODO: Get this and other params from input
            // TODO: don't forget about height
            // TODO: read height - 1's hash from the contract, and compare
            // with the prevhash result from the short header proof
            // reject L2 block if they don't match
            let _input = tx.input();
            let l1_hash = [0u8; 32];
            match shp_provider.get_and_verify_short_header_proof_by_l1_hash(l1_hash) {
                Ok(true) => {}
                Ok(false) => {
                    // Failed to verify shp
                    return Err(SoftConfirmationModuleCallError::ShortHeaderProofVerificationError);
                }
                Err(ShortHeaderProofProviderError::ShortHeaderProofNotFound) => {
                    return Err(SoftConfirmationModuleCallError::ShortHeaderProofNotFound);
                }
            }
            native_error!("System transaction found in user txs");
            return Err(SoftConfirmationModuleCallError::EvmMisplacedSystemTx);
        }

        // if tx is eip4844 error out
        if tx.is_eip4844() {
            native_error!("EIP-4844 transaction is not supported");
            return Err(SoftConfirmationModuleCallError::EvmTxTypeNotSupported(
                "EIP-4844".to_string(),
            ));
        }

        let result_and_state = evm.transact(tx).map_err(|e| {
            native_error!("Invalid tx {}. Error: {}", tx.hash(), e);
            match e {
                // only custom error we use is for not enough funds for L1 fee
                EVMError::Custom(_) => SoftConfirmationModuleCallError::EvmNotEnoughFundsForL1Fee,
                _ => SoftConfirmationModuleCallError::EvmTransactionExecutionError,
            }
        })?;

        // Check if the transaction used more gas than the available block gas limit
        if cumulative_gas_used + result_and_state.result.gas_used() > block_gas_limit {
            native_error!("Gas used exceeds block gas limit");
            return Err(
                SoftConfirmationModuleCallError::EvmGasUsedExceedsBlockGasLimit {
                    cumulative_gas: cumulative_gas_used,
                    tx_gas_used: result_and_state.result.gas_used(),
                    block_gas_limit,
                },
            );
        }

        native_trace!("Commiting tx to DB");
        evm.commit(result_and_state.state);
        cumulative_gas_used += result_and_state.result.gas_used();

        tx_results.push(result_and_state.result);
    }

    Ok(tx_results)
}

pub(crate) fn execute_system_txs<C: sov_modules_api::Context, EXT: CitreaExternalExt>(
    db: EvmDb<C>,
    block_env: BlockEnv,
    system_txs: &[TransactionSignedEcRecovered],
    config_env: CfgEnvWithHandlerCfg,
    ext: &mut EXT,
) -> Vec<ExecutionResult> {
    let citrea_spec = db.citrea_spec;
    let mut evm = CitreaEvm::new(db, citrea_spec, block_env, config_env, ext);

    system_txs
        .iter()
        .map(|tx| {
            evm.transact_commit(tx)
                .expect("System transactions must never fail")
        })
        .collect()
}
