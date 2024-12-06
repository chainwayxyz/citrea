use alloy_primitives::B256;
use citrea_primitives::basefee::calculate_next_block_base_fee;
use reth_primitives::{Bloom, Bytes, U256};
use revm::primitives::{BlobExcessGasAndPrice, BlockEnv, SpecId};
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::prelude::*;
use sov_modules_api::{AccessoryWorkingSet, WorkingSet};
use sov_state::Storage;
#[cfg(feature = "native")]
use tracing::instrument;

use crate::evm::primitive_types::Block;
use crate::evm::system_events::SystemEvent;
use crate::{citrea_spec_id_to_evm_spec_id, Evm};

impl<C: sov_modules_api::Context> Evm<C>
where
    <C::Storage as Storage>::Root: Into<[u8; 32]>,
{
    /// Logic executed at the beginning of the slot. Here we set the state root of the previous head.
    #[cfg_attr(
        feature = "native",
        instrument(level = "trace", skip(self, working_set), ret)
    )]
    pub fn begin_soft_confirmation_hook(
        &mut self,
        soft_confirmation_info: &HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        // just to be sure, we clear the pending transactions
        // do not ever think about removing this line
        // it has implications way beyond our understanding
        // a holy line
        self.pending_transactions.clear();
        // we have to set blob gas used to zero at the beginning of the block
        self.blob_gas_used = 0;

        let mut parent_block = self
            .head
            .get(working_set)
            .expect("Head block should always be set");

        parent_block.header.state_root = B256::from_slice(&soft_confirmation_info.pre_state_root);
        self.head.set(&parent_block, working_set);

        let sealed_parent_block = parent_block.clone().seal();
        let last_block_hash = sealed_parent_block.header.hash();

        // since we know the previous state root only here, we can set the last block hash
        self.latest_block_hashes.set(
            &U256::from(parent_block.header.number),
            &last_block_hash,
            working_set,
        );

        // populate system events
        let mut system_events = vec![];
        if let Some(last_l1_hash) = self.last_l1_hash.get(working_set) {
            if last_l1_hash != soft_confirmation_info.da_slot_hash {
                // That's a new L1 block
                system_events.push(SystemEvent::BitcoinLightClientSetBlockInfo(
                    soft_confirmation_info.da_slot_hash,
                    soft_confirmation_info.da_slot_txs_commitment,
                ));
            }
        } else {
            // That's the first L2 block in the first seen L1 block.
            system_events.push(SystemEvent::BitcoinLightClientInitialize(
                soft_confirmation_info.da_slot_height,
            ));
            system_events.push(SystemEvent::BitcoinLightClientSetBlockInfo(
                soft_confirmation_info.da_slot_hash,
                soft_confirmation_info.da_slot_txs_commitment,
            ));
            system_events.push(SystemEvent::BridgeInitialize);
        }

        soft_confirmation_info
            .deposit_data
            .iter()
            .for_each(|params| {
                system_events.push(SystemEvent::BridgeDeposit(params.clone()));
            });

        let cfg = self
            .cfg
            .get(working_set)
            .expect("EVM chain config should be set");
        let basefee = calculate_next_block_base_fee(
            parent_block.header.gas_used as u128,
            parent_block.header.gas_limit as u128,
            parent_block.header.base_fee_per_gas.unwrap_or_default(),
            cfg.base_fee_params,
        );

        let active_evm_spec = citrea_spec_id_to_evm_spec_id(soft_confirmation_info.current_spec);

        let blob_excess_gas_and_price = sealed_parent_block
            .header
            .next_block_excess_blob_gas()
            .or_else(|| {
                if active_evm_spec >= SpecId::CANCUN {
                    Some(0)
                } else {
                    None
                }
            })
            .map(BlobExcessGasAndPrice::new);

        let new_pending_env = BlockEnv {
            number: U256::from(parent_block.header.number + 1),
            coinbase: cfg.coinbase,
            timestamp: U256::from(soft_confirmation_info.timestamp),
            prevrandao: Some(soft_confirmation_info.da_slot_hash.into()),
            basefee: U256::from(basefee),
            gas_limit: U256::from(cfg.block_gas_limit),
            difficulty: U256::ZERO,
            blob_excess_gas_and_price,
        };

        // set early. so that if underlying calls use `self.block_env`
        // they don't use the wrong value
        self.block_env = new_pending_env.clone();

        if !system_events.is_empty() {
            self.execute_system_events(
                system_events,
                soft_confirmation_info.l1_fee_rate(),
                cfg,
                new_pending_env.clone(),
                active_evm_spec,
                working_set,
            );
        }

        // if height > 256, start removing the oldest block
        // keeping only 256 most recent blocks
        // this first happens on txs in block 257
        // remove block 0, keep blocks 1-256
        // then on block 258
        // remove block 1, keep blocks 2-257
        if new_pending_env.number > U256::from(256) {
            self.latest_block_hashes
                .remove(&(new_pending_env.number - U256::from(257)), working_set);
        }

        self.last_l1_hash
            .set(&soft_confirmation_info.da_slot_hash.into(), working_set);
    }

    /// Logic executed at the end of the slot. Here, we generate an authenticated block and set it as the new head of the chain.
    /// It's important to note that the state root hash is not known at this moment, so we postpone setting this field until the begin_slot_hook of the next slot.
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, ret))]
    pub fn end_soft_confirmation_hook(
        &mut self,
        soft_confirmation_info: &HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        let l1_hash = soft_confirmation_info.da_slot_hash;

        let parent_block = self
            .head
            .get(working_set)
            .expect("Head block should always be set")
            .seal();

        let expected_block_number = parent_block.header.number + 1;
        assert_eq!(
            self.block_env.number,
            U256::from(expected_block_number),
            "Pending head must be set to block {}, but found block {}",
            expected_block_number,
            self.block_env.number
        );

        let pending_transactions = &mut self.pending_transactions;

        let start_tx_index = parent_block.transactions.end;

        let gas_used = pending_transactions
            .last()
            .map_or(0u64, |tx| tx.receipt.receipt.cumulative_gas_used);

        let transactions: Vec<&reth_primitives::TransactionSigned> = pending_transactions
            .iter()
            .map(|tx| &tx.transaction.signed_transaction)
            .collect();

        let receipts: Vec<reth_primitives::ReceiptWithBloom> = pending_transactions
            .iter()
            .map(|tx| tx.receipt.receipt.clone().with_bloom())
            .collect();

        let header = reth_primitives::Header {
            parent_hash: parent_block.header.hash(),
            timestamp: self.block_env.timestamp.saturating_to(),
            number: self.block_env.number.saturating_to(),
            ommers_hash: reth_primitives::constants::EMPTY_OMMER_ROOT_HASH,
            beneficiary: parent_block.header.beneficiary,
            // This will be set in finalize_hook or in the next begin_slot_hook
            state_root: reth_primitives::constants::KECCAK_EMPTY,
            transactions_root: reth_primitives::proofs::calculate_transaction_root(
                transactions.as_slice(),
            ),
            receipts_root: reth_primitives::proofs::calculate_receipt_root(receipts.as_slice()),
            withdrawals_root: None,
            logs_bloom: receipts
                .iter()
                .fold(Bloom::ZERO, |bloom, r| bloom | r.bloom),
            difficulty: U256::ZERO,
            gas_limit: self.block_env.gas_limit.saturating_to(),
            gas_used,
            mix_hash: self.block_env.prevrandao.unwrap_or_default(),
            nonce: 0,
            base_fee_per_gas: Some(self.block_env.basefee.saturating_to()),
            extra_data: Bytes::default(),
            // EIP-4844 related fields
            // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
            blob_gas_used: if citrea_spec_id_to_evm_spec_id(soft_confirmation_info.current_spec)
                >= SpecId::CANCUN
            {
                Some(self.blob_gas_used)
            } else {
                None
            },
            excess_blob_gas: self
                .block_env
                .blob_excess_gas_and_price
                .as_ref()
                .map(|x| x.excess_blob_gas),
            // EIP-4788 related field
            // unrelated for rollups
            parent_beacon_block_root: None,
            requests_root: None,
        };

        let block = Block {
            header,
            l1_fee_rate: soft_confirmation_info.l1_fee_rate(),
            l1_hash: l1_hash.into(),
            transactions: start_tx_index..start_tx_index + pending_transactions.len() as u64,
        };

        self.head.set(&block, working_set);

        #[cfg(not(feature = "native"))]
        pending_transactions.clear();

        #[cfg(feature = "native")]
        {
            use crate::PendingTransaction;
            let mut accessory_state = working_set.accessory_state();
            self.pending_head.set(&block, &mut accessory_state);

            let mut tx_index = start_tx_index;
            for PendingTransaction {
                transaction,
                receipt,
            } in pending_transactions
            {
                self.transactions.push(transaction, &mut accessory_state);
                self.receipts.push(receipt, &mut accessory_state);

                self.transaction_hashes.set(
                    &transaction.signed_transaction.hash,
                    &tx_index,
                    &mut accessory_state,
                );

                tx_index += 1
            }
            self.pending_transactions.clear();
        }
    }

    /// This logic is executed after calculating the root hash.
    /// At this point, it is impossible to alter state variables because the state root is fixed.
    /// However, non-state data can be modified.
    /// This function's purpose is to add the block to the (non-authenticated) blocks structure,
    /// enabling block-related RPC queries.
    #[cfg_attr(
        feature = "native",
        instrument(level = "trace", skip(self, accessory_working_set), ret)
    )]
    #[cfg_attr(not(feature = "native"), allow(unused_variables))]
    pub fn finalize_hook(
        &self,
        root_hash: &<C::Storage as Storage>::Root,
        accessory_working_set: &mut AccessoryWorkingSet<C::Storage>,
    ) {
        #[cfg(feature = "native")]
        {
            let expected_block_number = self.blocks.len(accessory_working_set) as u64;

            let mut block = self
                .pending_head
                .get(accessory_working_set)
                .unwrap_or_else(|| {
                    panic!(
                        "Pending head must be set to block {}, but was empty",
                        expected_block_number
                    )
                });

            assert_eq!(
                block.header.number, expected_block_number,
                "Pending head must be set to block {}, but found block {}",
                expected_block_number, block.header.number
            );

            let root_hash_bytes: [u8; 32] = root_hash.clone().into();
            block.header.state_root = root_hash_bytes.into();

            let sealed_block = block.seal();

            self.blocks.push(&sealed_block, accessory_working_set);
            self.block_hashes.set(
                &sealed_block.header.hash(),
                &sealed_block.header.number,
                accessory_working_set,
            );
            self.pending_head.delete(accessory_working_set);
        }
    }
}
