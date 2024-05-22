use alloy_primitives::B256;
use reth_primitives::{Bloom, Bytes, U256};
use sov_modules_api::hooks::HookSoftConfirmationInfo;
use sov_modules_api::prelude::*;
use sov_modules_api::{AccessoryWorkingSet, Spec, WorkingSet};
use sov_state::Storage;
use tracing::instrument;

use crate::evm::primitive_types::{Block, BlockEnv};
use crate::evm::system_events::SystemEvent;
use crate::{Evm, PendingTransaction};

impl<C: sov_modules_api::Context> Evm<C>
where
    <C::Storage as Storage>::Root: Into<[u8; 32]>,
{
    /// Logic executed at the beginning of the slot. Here we set the state root of the previous head.
    #[instrument(level = "trace", skip(self, working_set), ret)]
    pub fn begin_soft_confirmation_hook(
        &self,
        soft_confirmation_info: &HookSoftConfirmationInfo,
        working_set: &mut WorkingSet<C>,
    ) {
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
            system_events.push(SystemEvent::BridgeInitialize(
                // couldn't figure out how encoding worked lol
                vec![
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 249, 114, 91, 99, 254, 20, 239, 175, 124, 199, 5, 186, 78, 92, 85,
                    160, 61, 80, 233, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 181, 210, 32, 93, 175, 87, 112, 72, 197,
                    229, 169, 167, 93, 10, 146, 78, 208, 62, 34, 108, 51, 4, 244, 162, 240, 28,
                    101, 202, 29, 171, 115, 82, 46, 107, 139, 173, 32, 98, 40, 235, 166, 83, 207,
                    24, 25, 188, 252, 27, 200, 88, 99, 14, 90, 227, 115, 238, 193, 169, 146, 67,
                    34, 165, 254, 132, 69, 197, 231, 96, 39, 173, 32, 21, 33, 214, 95, 100, 190,
                    63, 113, 183, 28, 164, 98, 34, 15, 19, 199, 123, 37, 16, 39, 246, 202, 68, 58,
                    72, 51, 83, 169, 111, 188, 226, 34, 173, 32, 15, 171, 238, 210, 105, 105, 78,
                    232, 61, 155, 51, 67, 165, 113, 32, 46, 104, 175, 101, 208, 95, 237, 166, 29,
                    190, 208, 196, 189, 178, 86, 166, 234, 173, 32, 0, 50, 109, 111, 114, 28, 3,
                    220, 95, 29, 136, 23, 216, 248, 238, 137, 10, 149, 162, 238, 218, 13, 77, 154,
                    1, 177, 204, 155, 123, 27, 114, 77, 172, 0, 99, 6, 99, 105, 116, 114, 101, 97,
                    20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 8, 0, 0, 0, 0, 5, 245,
                    225, 0, 104, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            ));
        }

        soft_confirmation_info
            .deposit_data
            .iter()
            .for_each(|deposit_data| {
                system_events.push(SystemEvent::BridgeDeposit(deposit_data.clone()));
            });

        let cfg = self
            .cfg
            .get(working_set)
            .expect("EVM chain config should be set");
        let new_pending_env = BlockEnv {
            number: parent_block.header.number + 1,
            coinbase: cfg.coinbase,
            timestamp: soft_confirmation_info.timestamp,
            prevrandao: soft_confirmation_info.da_slot_hash.into(),
            basefee: parent_block
                .header
                .next_block_base_fee(cfg.base_fee_params)
                .unwrap(),
            gas_limit: cfg.block_gas_limit,
        };

        self.block_env.set(&new_pending_env, working_set);
        self.l1_fee_rate
            .set(&soft_confirmation_info.l1_fee_rate, working_set);

        if !system_events.is_empty() {
            self.execute_system_events(system_events, working_set);
        }

        // if height > 256, start removing the oldest block
        // keeping only 256 most recent blocks
        // this first happens on txs in block 257
        // remove block 0, keep blocks 1-256
        // then on block 258
        // remove block 1, keep blocks 2-257
        if new_pending_env.number > 256 {
            self.latest_block_hashes
                .remove(&U256::from(new_pending_env.number - 257), working_set);
        }
        self.last_l1_hash
            .set(&soft_confirmation_info.da_slot_hash.into(), working_set);
    }

    /// Logic executed at the end of the slot. Here, we generate an authenticated block and set it as the new head of the chain.
    /// It's important to note that the state root hash is not known at this moment, so we postpone setting this field until the begin_slot_hook of the next slot.
    #[instrument(level = "trace", skip_all, ret)]
    pub fn end_soft_confirmation_hook(&self, working_set: &mut WorkingSet<C>) {
        let cfg = self
            .cfg
            .get(working_set)
            .expect("EVM chain config should be set");

        let block_env = self
            .block_env
            .get(working_set)
            .expect("Pending block should always be set");

        let l1_fee_rate = self
            .l1_fee_rate
            .get(working_set)
            .expect("L1 fee rate must be set");

        let l1_hash = self
            .last_l1_hash
            .get(working_set)
            .expect("Last L1 hash must be set");

        let parent_block = self
            .head
            .get(working_set)
            .expect("Head block should always be set")
            .seal();

        let expected_block_number = parent_block.header.number + 1;
        assert_eq!(
            block_env.number, expected_block_number,
            "Pending head must be set to block {}, but found block {}",
            expected_block_number, block_env.number
        );

        let pending_transactions: Vec<PendingTransaction> =
            self.pending_transactions.iter(working_set).collect();

        self.pending_transactions.clear(working_set);

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
            timestamp: block_env.timestamp,
            number: block_env.number,
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
            gas_limit: block_env.gas_limit,
            gas_used,
            mix_hash: block_env.prevrandao,
            nonce: 0,
            base_fee_per_gas: parent_block.header.next_block_base_fee(cfg.base_fee_params),
            extra_data: Bytes::default(),
            // EIP-4844 related fields
            // https://github.com/Sovereign-Labs/sovereign-sdk/issues/912
            blob_gas_used: None,
            excess_blob_gas: None,
            // EIP-4788 related field
            // unrelated for rollups
            parent_beacon_block_root: None,
        };

        let block = Block {
            header,
            l1_fee_rate,
            l1_hash,
            transactions: start_tx_index..start_tx_index + pending_transactions.len() as u64,
        };

        self.head.set(&block, working_set);

        let mut accessory_state = working_set.accessory_state();
        self.pending_head.set(&block, &mut accessory_state);

        let mut tx_index = start_tx_index;
        for PendingTransaction {
            transaction,
            receipt,
        } in &pending_transactions
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

        self.pending_transactions.clear(working_set);
    }

    /// This logic is executed after calculating the root hash.
    /// At this point, it is impossible to alter state variables because the state root is fixed.
    /// However, non-state data can be modified.
    /// This function's purpose is to add the block to the (non-authenticated) blocks structure,
    /// enabling block-related RPC queries.
    #[instrument(level = "trace", skip(self, accessory_working_set), ret)]
    pub fn finalize_hook(
        &self,
        root_hash: &<<C as Spec>::Storage as Storage>::Root,
        accessory_working_set: &mut AccessoryWorkingSet<C>,
    ) {
        if cfg!(feature = "native") {
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

            self.l1_fee_failed_txs.clear(accessory_working_set);
        }
    }
}
