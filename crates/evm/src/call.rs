use core::panic;

use alloy_consensus::TxReceipt;
use reth_primitives::{Recovered, TransactionSigned};
use revm::context::CfgEnv;
use revm::primitives::hardfork::SpecId;
use sov_modules_api::prelude::*;
use sov_modules_api::{CallResponse, L2BlockModuleCallError, WorkingSet};

use crate::conversions::ConversionError;
use crate::evm::db::EvmDb;
use crate::evm::executor::{self};
use crate::evm::handler::{CitreaChain, CitreaChainExt};
use crate::evm::primitive_types::{CitreaReceiptWithBloom, TransactionSignedAndRecovered};
use crate::evm::{EvmChainConfig, RlpEvmTransaction};
use crate::{citrea_spec_id_to_evm_spec_id, Evm, PendingTransaction};

/// EVM call message.
#[derive(
    borsh::BorshDeserialize,
    borsh::BorshSerialize,
    Debug,
    PartialEq,
    Clone,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct CallMessage {
    /// RLP encoded transaction.
    pub txs: Vec<RlpEvmTransaction>,
}

impl<C: sov_modules_api::Context> Evm<C> {
    // so we don't convert errors twice
    /// Executes a call message.
    pub(crate) fn execute_call(
        &mut self,
        txs: Vec<RlpEvmTransaction>,
        context: &C,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<CallResponse, L2BlockModuleCallError> {
        // use of `self.block_env` is allowed here

        let users_txs: Vec<Recovered<TransactionSigned>> = txs
            .into_iter()
            .map(|tx| tx.try_into())
            .collect::<Result<Vec<_>, ConversionError>>()
            .map_err(|_| L2BlockModuleCallError::EvmTxNotSerializable)?;

        let cfg = self.cfg.get(working_set).expect("Evm config must be set");
        let active_evm_spec = citrea_spec_id_to_evm_spec_id(context.active_spec());
        let cfg_env = get_cfg_env(cfg, active_evm_spec);

        let l1_fee_rate = context.l1_fee_rate();
        let mut citrea_handler_ext = CitreaChain::new(l1_fee_rate);

        let block_number = self.block_env.number;
        let mut cumulative_gas_used = 0;
        let mut log_index_start = 0;

        if let Some(tx) = self.pending_transactions.last() {
            cumulative_gas_used = tx.receipt.receipt.cumulative_gas_used();
            log_index_start = tx.receipt.log_index_start + tx.receipt.receipt.logs().len() as u64;
        }

        // since self is going to be borrowed in get_db
        // we copy the value of should_be_end_of_sys_txs
        // and pass it to executor as mutable reference
        // then we update the value of self.should_be_end_of_sys_txs
        // with the new value
        //
        // This whole scheme is done to avoid having to sov-tx for EVM module where each have
        // system txs at the beginnging of their respective calls
        let mut should_be_end_of_sys_txs = self.should_be_end_of_sys_txs;

        let evm_db: EvmDb<'_, C> = self.get_db(working_set);

        let results = executor::execute_multiple_tx(
            evm_db,
            self.block_env.clone(),
            &users_txs,
            cfg_env,
            &mut citrea_handler_ext,
            cumulative_gas_used,
            context.slot_height(),
            &mut should_be_end_of_sys_txs,
        )?;

        self.should_be_end_of_sys_txs = should_be_end_of_sys_txs;

        // Iterate each evm_txs_recovered and results pair
        // Create a PendingTransaction for each pair
        // Push each PendingTransaction to pending_transactions
        for (evm_tx_recovered, result) in users_txs.into_iter().zip(results.into_iter()) {
            let gas_used = result.gas_used();
            cumulative_gas_used += gas_used;
            let tx_hash = evm_tx_recovered.hash();
            let tx_info = citrea_handler_ext
                .get_tx_info(tx_hash)
                .unwrap_or_else(|| panic!("evm: Could not get associated info for tx: {tx_hash}"));

            let success = result.is_success();

            let logs = result.into_logs();
            let logs_len = logs.len() as u64;

            let receipt = CitreaReceiptWithBloom {
                receipt: reth_primitives::Receipt {
                    tx_type: evm_tx_recovered.tx_type(),
                    success,
                    cumulative_gas_used,
                    logs,
                }
                .into(),
                gas_used,
                log_index_start,
                l1_diff_size: tx_info.l1_diff_size,
            };

            log_index_start += logs_len;

            let (signed_transaction, signer) = evm_tx_recovered.into_parts();

            let pending_transaction = PendingTransaction {
                transaction: TransactionSignedAndRecovered {
                    signer,
                    signed_transaction,
                    block_number,
                },
                receipt,
            };

            self.pending_transactions.push(pending_transaction);
        }
        Ok(CallResponse::default())
    }
}

/// Get cfg env for a given block number
/// Returns correct config depending on spec for given block number
pub(crate) fn get_cfg_env(cfg: EvmChainConfig, spec_id: SpecId) -> CfgEnv {
    let mut cfg_env = CfgEnv::new_with_spec(spec_id);
    cfg_env.chain_id = cfg.chain_id;
    cfg_env.limit_contract_code_size = cfg.limit_contract_code_size;
    cfg_env
}
