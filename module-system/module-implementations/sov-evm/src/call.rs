use core::panic;

use anyhow::Result;
use reth_primitives::TransactionSignedEcRecovered;
use revm::primitives::{CfgEnvWithHandlerCfg, EVMError, SpecId};
use sov_modules_api::prelude::*;
use sov_modules_api::{CallResponse, WorkingSet};

use crate::evm::db::EvmDb;
use crate::evm::executor::{self};
use crate::evm::handler::{CitreaExternal, CitreaExternalExt};
use crate::evm::primitive_types::{BlockEnv, Receipt, TransactionSignedAndRecovered};
use crate::evm::{EvmChainConfig, RlpEvmTransaction};
use crate::{Evm, PendingTransaction};

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    derive(serde::Deserialize)
)]

/// EVM call message.
#[derive(borsh::BorshDeserialize, borsh::BorshSerialize, Debug, PartialEq, Clone)]
pub struct CallMessage {
    /// RLP encoded transaction.
    pub txs: Vec<RlpEvmTransaction>,
}

impl<C: sov_modules_api::Context> Evm<C> {
    /// Executes a call message.
    pub(crate) fn execute_call(
        &self,
        txs: Vec<RlpEvmTransaction>,
        _context: &C,
        working_set: &mut WorkingSet<C>,
    ) -> Result<CallResponse> {
        let evm_txs_recovered: Vec<TransactionSignedEcRecovered> = txs
            .into_iter()
            .filter_map(|tx| match tx.try_into() {
                Ok(tx) => Some(tx),
                Err(_) => None,
            })
            .collect();

        let block_env = self
            .block_env
            .get(working_set)
            .expect("Pending block must be set");

        let cfg = self.cfg.get(working_set).expect("Evm config must be set");
        let cfg_env: CfgEnvWithHandlerCfg = get_cfg_env(&block_env, cfg, None);

        let l1_fee_rate = self
            .l1_fee_rate
            .get(working_set)
            .expect("L1 fee rate must be set");
        let mut citrea_handler_ext = CitreaExternal::new(l1_fee_rate);

        let block_number = block_env.number;
        let evm_db: EvmDb<'_, C> = self.get_db(working_set);
        let results = executor::execute_multiple_tx(
            evm_db,
            block_env,
            &evm_txs_recovered,
            cfg_env,
            &mut citrea_handler_ext,
        );

        // Iterate each evm_txs_recovered and results pair
        // Create a PendingTransaction for each pair
        // Push each PendingTransaction to pending_transactions
        for (evm_tx_recovered, result) in evm_txs_recovered.into_iter().zip(results.into_iter()) {
            let previous_transaction = self.pending_transactions.last(working_set);
            let previous_transaction_cumulative_gas_used = previous_transaction
                .as_ref()
                .map_or(0u64, |tx| tx.receipt.receipt.cumulative_gas_used);
            let log_index_start = previous_transaction.as_ref().map_or(0u64, |tx| {
                tx.receipt.log_index_start + tx.receipt.receipt.logs.len() as u64
            });

            match result {
                Ok(result) => {
                    // take ownership of result.log() and use into()
                    let logs: Vec<_> = result.logs().iter().cloned().map(Into::into).collect();

                    let gas_used = result.gas_used();
                    let tx_hash = evm_tx_recovered.hash();
                    let tx_info = citrea_handler_ext.get_tx_info(tx_hash).unwrap_or_else(|| {
                        panic!("evm: Could not get associated info for tx: {tx_hash}")
                    });

                    let receipt = Receipt {
                        receipt: reth_primitives::Receipt {
                            tx_type: evm_tx_recovered.tx_type(),
                            success: result.is_success(),
                            cumulative_gas_used: previous_transaction_cumulative_gas_used
                                + gas_used,
                            logs,
                        },
                        gas_used,
                        log_index_start,
                        diff_size: tx_info.diff_size,
                        error: None,
                    };

                    let pending_transaction = PendingTransaction {
                        transaction: TransactionSignedAndRecovered {
                            signer: evm_tx_recovered.signer(),
                            signed_transaction: evm_tx_recovered.into(),
                            block_number,
                        },
                        receipt,
                    };

                    self.pending_transactions
                        .push(&pending_transaction, working_set);
                }
                // Adopted from https://github.com/paradigmxyz/reth/blob/main/crates/payload/basic/src/lib.rs#L884
                Err(err) => match err {
                    EVMError::Transaction(_) => {
                        tracing::debug!("evm: Transaction error: {:?}", err);
                        // This is a transactional error, so we can skip it without doing anything.
                        continue;
                    }
                    err => {
                        tracing::debug!("evm: Transaction error: {:?}", err);
                        // This is a fatal error, so we need to return it.
                        return Err(err.into());
                    }
                },
            }
        }
        Ok(CallResponse::default())
    }
}

/// Get cfg env for a given block number
/// Returns correct config depending on spec for given block number
/// Copies context dependent values from template_cfg or default if not provided
pub(crate) fn get_cfg_env(
    block_env: &BlockEnv,
    cfg: EvmChainConfig,
    template_cfg: Option<CfgEnvWithHandlerCfg>,
) -> CfgEnvWithHandlerCfg {
    let mut cfg_env = template_cfg.unwrap_or(CfgEnvWithHandlerCfg::new_with_spec_id(
        Default::default(),
        get_spec_id(cfg.spec, block_env.number),
    ));
    cfg_env.chain_id = cfg.chain_id;
    cfg_env.limit_contract_code_size = cfg.limit_contract_code_size;
    cfg_env
}

/// Get spec id for a given block number
/// Returns the first spec id defined for block >= block_number
pub(crate) fn get_spec_id(spec: Vec<(u64, SpecId)>, block_number: u64) -> SpecId {
    match spec.binary_search_by(|&(k, _)| k.cmp(&block_number)) {
        Ok(index) => spec[index].1,
        Err(index) => {
            if index > 0 {
                spec[index - 1].1
            } else {
                // this should never happen as we cover this in genesis
                panic!("EVM spec must start from block 0")
            }
        }
    }
}
