use core::panic;

use anyhow::Result;
use reth_primitives::TransactionSignedEcRecovered;
use revm::primitives::{CfgEnv, CfgEnvWithHandlerCfg, EVMError, SpecId};
use sov_modules_api::prelude::*;
use sov_modules_api::{native_error, CallResponse, WorkingSet};

use crate::evm::db::EvmDb;
use crate::evm::executor::{self};
use crate::evm::handler::{CitreaExternal, CitreaExternalExt};
use crate::evm::primitive_types::{BlockEnv, Receipt, TransactionSignedAndRecovered};
use crate::evm::{EvmChainConfig, RlpEvmTransaction};
use crate::system_contracts::{BitcoinLightClient, Bridge};
use crate::system_events::{create_system_transactions, SYSTEM_SIGNER};
use crate::{Evm, PendingTransaction, SystemEvent};

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
    /// Executes system events for the current block and push tx to pending_transactions.
    pub(crate) fn execute_system_events(
        &mut self,
        system_events: Vec<SystemEvent>,
        l1_fee_rate: u128,
        cfg: EvmChainConfig,
        block_env: BlockEnv,
        working_set: &mut WorkingSet<C>,
    ) {
        // don't use self.block_env here
        // function is expected to use block_env passed as argument

        let cfg_env: CfgEnvWithHandlerCfg = get_cfg_env(&block_env, cfg);

        let l1_block_hash_exists = self
            .accounts
            .get(&BitcoinLightClient::address(), working_set)
            .is_some();
        if !l1_block_hash_exists {
            native_error!("System contract not found: BitcoinLightClient");
            return;
        }

        let bridge_contract_exists = self.accounts.get(&Bridge::address(), working_set).is_some();
        if !bridge_contract_exists {
            native_error!("System contract not found: Bridge");
            return;
        }

        let system_nonce = self
            .accounts
            .get(&SYSTEM_SIGNER, working_set)
            .map(|info| info.nonce)
            .unwrap_or(0);

        let db: EvmDb<'_, C> = self.get_db(working_set);
        let system_txs = create_system_transactions(system_events, system_nonce, cfg_env.chain_id);

        let mut citrea_handler_ext = CitreaExternal::new(l1_fee_rate);
        let block_number = block_env.number;
        let tx_results = executor::execute_system_txs(
            db,
            block_env,
            &system_txs,
            cfg_env,
            &mut citrea_handler_ext,
        );

        let mut cumulative_gas_used = 0;
        let mut log_index_start = 0;

        assert!(self.pending_transactions.is_empty());

        for (tx, result) in system_txs.into_iter().zip(tx_results.into_iter()) {
            let logs: Vec<_> = result.logs().iter().cloned().map(Into::into).collect();
            let logs_len = logs.len() as u64;
            let gas_used = result.gas_used();
            cumulative_gas_used += gas_used;
            let tx_hash = tx.hash();
            let tx_info = citrea_handler_ext
                .get_tx_info(tx_hash)
                .unwrap_or_else(|| panic!("evm: Could not get associated info for tx: {tx_hash}"));
            let receipt = Receipt {
                receipt: reth_primitives::Receipt {
                    tx_type: tx.tx_type(),
                    success: result.is_success(),
                    cumulative_gas_used,
                    logs,
                },
                gas_used: gas_used as u128,
                log_index_start,
                l1_diff_size: tx_info.l1_diff_size,
            };
            log_index_start += logs_len;

            let pending_transaction = PendingTransaction {
                transaction: TransactionSignedAndRecovered {
                    signer: tx.signer(),
                    signed_transaction: tx.into(),
                    block_number,
                },
                receipt,
            };
            #[cfg(feature = "native")]
            {
                self.native_pending_transactions
                    .push(&pending_transaction, &mut working_set.accessory_state());
            }

            self.pending_transactions.push(pending_transaction);
        }
    }

    /// Executes a call message.
    pub(crate) fn execute_call(
        &mut self,
        txs: Vec<RlpEvmTransaction>,
        context: &C,
        working_set: &mut WorkingSet<C>,
    ) -> Result<CallResponse> {
        // use of `self.block_env` is allowed here

        let users_txs: Vec<TransactionSignedEcRecovered> = txs
            .into_iter()
            .filter_map(|tx| match tx.try_into() {
                Ok(tx) => Some(tx),
                Err(_) => None,
            })
            .collect();

        let cfg = self.cfg.get(working_set).expect("Evm config must be set");
        let cfg_env: CfgEnvWithHandlerCfg = get_cfg_env(&self.block_env, cfg);

        let l1_fee_rate = context.l1_fee_rate();
        let mut citrea_handler_ext = CitreaExternal::new(l1_fee_rate);

        let block_number = self.block_env.number;
        let mut cumulative_gas_used = 0;
        let mut log_index_start = 0;

        if let Some(tx) = self.pending_transactions.last() {
            cumulative_gas_used = tx.receipt.receipt.cumulative_gas_used;
            log_index_start = tx.receipt.log_index_start + tx.receipt.receipt.logs.len() as u64;
        }

        let evm_db: EvmDb<'_, C> = self.get_db(working_set);

        let results = executor::execute_multiple_tx(
            evm_db,
            self.block_env,
            &users_txs,
            cfg_env,
            &mut citrea_handler_ext,
            cumulative_gas_used,
        );

        // Iterate each evm_txs_recovered and results pair
        // Create a PendingTransaction for each pair
        // Push each PendingTransaction to pending_transactions
        for (evm_tx_recovered, result) in users_txs.into_iter().zip(results.into_iter()) {
            match result {
                Ok(result) => {
                    // take ownership of result.log() and use into()
                    let logs: Vec<_> = result.logs().iter().cloned().map(Into::into).collect();
                    let logs_len = logs.len() as u64;

                    let gas_used = result.gas_used();
                    cumulative_gas_used += gas_used;
                    let tx_hash = evm_tx_recovered.hash();
                    let tx_info = citrea_handler_ext.get_tx_info(tx_hash).unwrap_or_else(|| {
                        panic!("evm: Could not get associated info for tx: {tx_hash}")
                    });

                    let receipt = Receipt {
                        receipt: reth_primitives::Receipt {
                            tx_type: evm_tx_recovered.tx_type(),
                            success: result.is_success(),
                            cumulative_gas_used,
                            logs,
                        },
                        gas_used: gas_used as u128,
                        log_index_start,
                        l1_diff_size: tx_info.l1_diff_size,
                    };
                    log_index_start += logs_len;

                    let pending_transaction = PendingTransaction {
                        transaction: TransactionSignedAndRecovered {
                            signer: evm_tx_recovered.signer(),
                            signed_transaction: evm_tx_recovered.into(),
                            block_number,
                        },
                        receipt,
                    };

                    #[cfg(feature = "native")]
                    {
                        self.native_pending_transactions
                            .push(&pending_transaction, &mut working_set.accessory_state());
                    }

                    self.pending_transactions.push(pending_transaction);
                }
                // Adopted from https://github.com/paradigmxyz/reth/blob/main/crates/payload/basic/src/lib.rs#L884
                Err(err) => match err {
                    EVMError::Transaction(_) => {
                        native_error!("evm: Transaction error: {:?}", err);
                        // This is a transactional error, so we can skip it without doing anything.
                        continue;
                    }
                    EVMError::Custom(msg) => {
                        #[cfg(feature = "native")]
                        if !msg.starts_with("Gas used") {
                            // not really good way to seperate these transactions but it's the best we can do for now
                            // TODO: replace this branching with a better one.
                            self.l1_fee_failed_txs
                                .push(&evm_tx_recovered.hash(), &mut working_set.accessory_state());
                        }
                        // This is a custom error - we need to log it but no need to shutdown the system as of now.
                        native_error!("evm: Custom error: {:?}", msg);
                        continue;
                    }
                    err => {
                        native_error!("evm: Transaction error: {:?}", err);
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
pub(crate) fn get_cfg_env(block_env: &BlockEnv, cfg: EvmChainConfig) -> CfgEnvWithHandlerCfg {
    let mut cfg_env = CfgEnvWithHandlerCfg::new_with_spec_id(
        CfgEnv::default(),
        get_spec_id(cfg.spec, block_env.number),
    );
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
