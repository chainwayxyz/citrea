use alloy_consensus::Header as AlloyHeader;
use alloy_primitives::{Bloom, Bytes, B256, B64, U256};
use citrea_primitives::basefee::calculate_next_block_base_fee;
use citrea_primitives::PRE_FORK2_BRIDGE_INITIALIZE_PARAMS;
use revm::primitives::{BlobExcessGasAndPrice, BlockEnv, SpecId};
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::prelude::*;
use sov_modules_api::{AccessoryWorkingSet, WorkingSet};
use sov_rollup_interface::spec::SpecId as CitreaSpecId;
use sov_rollup_interface::zk::StorageRootHash;
#[cfg(feature = "native")]
use tracing::instrument;

use crate::evm::primitive_types::Block;
use crate::evm::system_events::SystemEvent;
use crate::{citrea_spec_id_to_evm_spec_id, Evm};

impl<C: sov_modules_api::Context> Evm<C> {
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

        let current_spec = soft_confirmation_info.current_spec();

        let parent_block = if current_spec >= CitreaSpecId::Kumquat {
            let mut parent_block = match self.head_rlp.get(working_set) {
                Some(block) => block,
                None => self
                    .head
                    .get(working_set)
                    .expect("Head block should always be set")
                    .into(),
            };

            parent_block.header.state_root =
                B256::from_slice(&soft_confirmation_info.pre_state_root());

            self.head_rlp.set(&parent_block, working_set);

            parent_block
        } else {
            let mut parent_block = self
                .head
                .get(working_set)
                .expect("Head block should always be set");

            parent_block.header.state_root =
                B256::from_slice(&soft_confirmation_info.pre_state_root());

            self.head.set(&parent_block, working_set);

            parent_block.into()
        };

        let parent_block_number = parent_block.header.number;
        let parent_block_base_fee_per_gas =
            parent_block.header.base_fee_per_gas.unwrap_or_default();
        let parent_block_gas_used = parent_block.header.gas_used;
        let parent_block_gas_limit = parent_block.header.gas_limit;

        let sealed_parent_block = parent_block.seal();
        let last_block_hash = sealed_parent_block.header.hash();

        // since we know the previous state root only here, we can set the last block hash
        self.latest_block_hashes.set(
            &U256::from(parent_block_number),
            &last_block_hash,
            working_set,
        );

        let mut system_events = vec![];
        // populate system events if active citrea spec is below fork2
        if current_spec < CitreaSpecId::Fork2 {
            system_events = populate_system_events(
                soft_confirmation_info.deposit_data().as_slice(),
                soft_confirmation_info
                    .da_slot_hash()
                    .expect("DA slot hash must exist for pre fork2 soft confirmation"),
                soft_confirmation_info
                    .da_slot_txs_commitment()
                    .expect("DA slot txs commitment must exist for pre fork2 soft confirmation"),
                soft_confirmation_info
                    .da_slot_height()
                    .expect("DA slot height must exist for pre fork2 soft confirmation"),
                self.last_l1_hash.get(working_set),
                PRE_FORK2_BRIDGE_INITIALIZE_PARAMS,
            )
        }

        let cfg = self
            .cfg
            .get(working_set)
            .expect("EVM chain config should be set");
        let basefee = calculate_next_block_base_fee(
            parent_block_gas_used,
            parent_block_gas_limit,
            parent_block_base_fee_per_gas,
            cfg.base_fee_params,
        );

        let active_evm_spec = citrea_spec_id_to_evm_spec_id(soft_confirmation_info.current_spec());

        let blob_excess_gas_and_price = if active_evm_spec >= SpecId::CANCUN {
            Some(BlobExcessGasAndPrice::new(0))
        } else {
            None
        };

        let new_pending_env = BlockEnv {
            number: U256::from(parent_block_number + 1),
            coinbase: cfg.coinbase,
            timestamp: U256::from(soft_confirmation_info.timestamp()),
            // TODO: https://github.com/chainwayxyz/citrea/issues/1978
            prevrandao: Some(
                soft_confirmation_info
                    .da_slot_hash()
                    .unwrap_or_default()
                    .into(),
            ),
            basefee: U256::from(basefee),
            gas_limit: U256::from(cfg.block_gas_limit),
            difficulty: U256::ZERO,
            blob_excess_gas_and_price,
        };

        // set early. so that if underlying calls use `self.block_env`
        // they don't use the wrong value
        self.block_env = new_pending_env.clone();

        // No need to check for fork, as the system events are only populated if the active citrea spec is below Fork2
        if !system_events.is_empty() {
            self.execute_system_events(
                system_events,
                soft_confirmation_info.l1_fee_rate(),
                cfg,
                new_pending_env,
                current_spec,
                working_set,
            );
        }

        if current_spec < CitreaSpecId::Fork2 {
            // There is no reason to remove them from the state at all.
            // We remove them only before Fork2 for backwards compatibility.

            // if height > 256, start removing the oldest block
            // keeping only 256 most recent blocks
            // this first happens on txs in block 257
            // remove block 0, keep blocks 1-256
            // then on block 258
            // remove block 1, keep blocks 2-257
            if self.block_env.number > U256::from(256) {
                self.latest_block_hashes
                    .remove(&(self.block_env.number - U256::from(257)), working_set);
            }
        }
        if current_spec < CitreaSpecId::Fork2 {
            self.last_l1_hash.set(
                &soft_confirmation_info.da_slot_hash().unwrap().into(),
                working_set,
            );
        }
    }

    /// Logic executed at the end of the slot. Here, we generate an authenticated block and set it as the new head of the chain.
    /// It's important to note that the state root hash is not known at this moment, so we postpone setting this field until the begin_slot_hook of the next slot.
    #[cfg_attr(feature = "native", instrument(level = "trace", skip_all, ret))]
    pub fn end_soft_confirmation_hook(
        &mut self,
        soft_confirmation_info: &HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) {
        // TODO: https://github.com/chainwayxyz/citrea/issues/1977
        let l1_hash = soft_confirmation_info.da_slot_hash().unwrap_or_default();

        let current_spec = soft_confirmation_info.current_spec();

        let parent_block = if current_spec >= CitreaSpecId::Kumquat {
            match self.head_rlp.get(working_set) {
                Some(block) => block.seal(),
                None => {
                    let block: Block<AlloyHeader> = self
                        .head
                        .get(working_set)
                        .expect("Head block should always be set")
                        .into();
                    block.seal()
                }
            }
        } else {
            self.head
                .get(working_set)
                .expect("Head block should always be set")
                .seal()
        };

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

        let header = AlloyHeader {
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
            nonce: B64::ZERO,
            base_fee_per_gas: Some(self.block_env.basefee.saturating_to()),
            extra_data: Bytes::default(),
            // EIP-4844 related fields
            // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
            blob_gas_used: if citrea_spec_id_to_evm_spec_id(soft_confirmation_info.current_spec())
                >= SpecId::CANCUN
            {
                Some(0)
            } else {
                None
            },
            excess_blob_gas: if citrea_spec_id_to_evm_spec_id(soft_confirmation_info.current_spec())
                >= SpecId::CANCUN
            {
                Some(0)
            } else {
                None
            },
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

        if current_spec >= CitreaSpecId::Kumquat {
            self.head_rlp.set(&block, working_set);
        } else {
            self.head.set(&block.clone().into(), working_set);
        }

        #[cfg(not(feature = "native"))]
        pending_transactions.clear();

        #[cfg(feature = "native")]
        {
            use crate::PendingTransaction;

            let mut accessory_state = working_set.accessory_state();

            self.pending_head.set(&block, &mut accessory_state);

            // migration start
            if self.transactions_rlp.len(&mut accessory_state) == 0 {
                let len = self.transactions.len(&mut accessory_state);
                tracing::info!("Migrating {} transactions from storage to RLP", len);
                for i in 0..len {
                    let tx = self.transactions.get(i, &mut accessory_state).unwrap();
                    self.transactions_rlp.push(&tx.into(), &mut accessory_state);
                }
            }

            if self.receipts_rlp.len(&mut accessory_state) == 0 {
                let len = self.receipts.len(&mut accessory_state);
                tracing::info!("Migrating {} receipts from storage to RLP", len);
                for i in 0..len {
                    let receipt = self.receipts.get(i, &mut accessory_state).unwrap();
                    self.receipts_rlp.push(&receipt, &mut accessory_state);
                }
            }
            // migration end

            let mut tx_index = start_tx_index;
            for PendingTransaction {
                transaction,
                receipt,
            } in pending_transactions
            {
                self.transactions_rlp
                    .push(transaction, &mut accessory_state);
                self.receipts_rlp.push(receipt, &mut accessory_state);

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
        root_hash: &StorageRootHash,
        accessory_working_set: &mut AccessoryWorkingSet<C::Storage>,
    ) {
        #[cfg(feature = "native")]
        {
            // migration start
            if self.blocks_rlp.len(accessory_working_set) == 0 {
                let len = self.blocks.len(accessory_working_set);
                tracing::info!("Migrating {} blocks from storage to RLP", len);
                for i in 0..len {
                    let block = self.blocks.get(i, accessory_working_set).unwrap();
                    self.blocks_rlp.push(&block.into(), accessory_working_set);
                }
            }
            // migration end

            let expected_block_number = self.blocks_rlp.len(accessory_working_set) as u64;

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

            block.header.state_root = root_hash.into();

            let sealed_block = block.seal();

            self.blocks_rlp.push(&sealed_block, accessory_working_set);
            self.block_hashes.set(
                &sealed_block.header.hash(),
                &sealed_block.header.number,
                accessory_working_set,
            );
            self.pending_head.delete(accessory_working_set);
        }
    }
}

/// TODO: https://github.com/chainwayxyz/citrea/issues/2013
/// Populates system events based on the current soft confirmation info.
pub fn populate_system_events<'a>(
    deposit_data: &[Vec<u8>],
    current_slot_hash: [u8; 32],
    current_da_txs_commitment: [u8; 32],
    current_da_height: u64,
    last_l1_hash_of_evm: Option<B256>,
    bridge_initialize_params: &'a [u8],
) -> Vec<SystemEvent<'a>> {
    let mut system_events = vec![];

    if let Some(last_l1_hash) = last_l1_hash_of_evm {
        if last_l1_hash != current_slot_hash {
            // That's a new L1 block
            system_events.push(SystemEvent::BitcoinLightClientSetBlockInfo(
                current_slot_hash,
                current_da_txs_commitment,
            ));
        }
    } else {
        // That's the first L2 block in the first seen L1 block.
        system_events.push(SystemEvent::BitcoinLightClientInitialize(current_da_height));
        system_events.push(SystemEvent::BitcoinLightClientSetBlockInfo(
            current_slot_hash,
            current_da_txs_commitment,
        ));
        system_events.push(SystemEvent::BridgeInitialize(bridge_initialize_params));
    }

    deposit_data.iter().for_each(|params| {
        system_events.push(SystemEvent::BridgeDeposit(params.clone()));
    });
    system_events
}
