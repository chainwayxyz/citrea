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

/// Default and maximum gas cap for `eth_call` and `debug_traceCall`, in gas units.
///
/// Set above the block gas limit so complex read-only calls can run, while still bounding the EVM
/// memory (~7 MiB at 100M gas) and CPU a single call can consume. This is also the hard ceiling:
/// [`RpcGasCap::new`] clamps any larger configured value down to it, so a misconfiguration cannot
/// lift that bound. Analogous to reth's `RPC_DEFAULT_GAS_CAP` (50M) and geth's
/// `RPCGasCap`, but higher. Keep in sync with the `default_gas_cap` used by `citrea_common`'s
/// `RpcConfig`.
pub const RPC_DEFAULT_GAS_CAP: u64 = 100_000_000;

/// Immutable gas cap for `eth_call` and `debug_traceCall`, constructed at RPC server startup from
/// `RpcConfig::gas_cap` via [`RpcGasCap::new`].
///
/// Each RPC server owns its cap and passes a copy into the EVM helpers for every request, so
/// another server or test cannot change its configuration. A value of 0 means "do not raise the
/// gas ceiling above the block gas limit".
#[derive(Clone, Copy, Debug)]
pub struct RpcGasCap(u64);

impl RpcGasCap {
    /// Constructs an RPC gas cap, clamped to at most [`RPC_DEFAULT_GAS_CAP`]. Use at RPC
    /// server startup; see [`Self::get`]. A value of 0 is preserved and means "do not raise the
    /// gas ceiling above the block gas limit".
    pub fn new(gas_cap: u64) -> Self {
        Self(gas_cap.min(RPC_DEFAULT_GAS_CAP))
    }

    /// Returns this instance's RPC gas cap for `eth_call` and `debug_traceCall`.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Default for RpcGasCap {
    fn default() -> Self {
        Self::new(RPC_DEFAULT_GAS_CAP)
    }
}

#[cfg(test)]
mod gas_cap_tests {
    use super::{RpcGasCap, RPC_DEFAULT_GAS_CAP};

    #[test]
    fn rpc_gas_cap_clamps_to_max_and_preserves_zero() {
        // A configured value above the maximum is clamped down to it.
        assert_eq!(
            RpcGasCap::new(RPC_DEFAULT_GAS_CAP + 50_000_000).get(),
            RPC_DEFAULT_GAS_CAP
        );
        // u64::MAX (the previously dangerous case) is clamped too.
        assert_eq!(RpcGasCap::new(u64::MAX).get(), RPC_DEFAULT_GAS_CAP);
        // A value below the maximum passes through unchanged.
        let lowered = RpcGasCap::new(30_000_000);
        assert_eq!(lowered.get(), 30_000_000);
        // 0 is preserved: "do not raise above the block gas limit".
        assert_eq!(RpcGasCap::new(0).get(), 0);
        // Constructing a default cap does not change an existing instance.
        assert_eq!(RpcGasCap::default().get(), RPC_DEFAULT_GAS_CAP);
        assert_eq!(lowered.get(), 30_000_000);
    }
}

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
        // system txs at the beginning of their respective calls
        let mut should_be_end_of_sys_txs = self.should_be_end_of_sys_txs;

        let evm_db: EvmDb<'_, C> = self.get_db(working_set, context.active_spec());

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
