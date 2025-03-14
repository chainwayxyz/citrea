use std::sync::Arc;

use alloy_primitives::ruint::aliases::U256;
use alloy_sol_types::SolCall;
use anyhow::anyhow;
use borsh::BorshDeserialize;
use citrea_evm::system_contracts::BitcoinLightClientContract;
use citrea_evm::{CallMessage as EvmCallMessage, SYSTEM_SIGNER};
use citrea_stf::runtime::DefaultContext;
use reth_primitives::TransactionSignedEcRecovered;
use sov_db::ledger_db::SharedLedgerOps;
use sov_modules_api::{DaSpec, SlotData};
use sov_rollup_interface::services::da::DaService;

use super::types::{PreFork2Transaction, SoftConfirmationResponse};

async fn update_short_header_proof_from_sys_tx<Da: DaService, DB: SharedLedgerOps>(
    tx: &TransactionSignedEcRecovered,
    ledger_db: &DB,
    da_service: Arc<Da>,
) -> anyhow::Result<Option<Da::FilteredBlock>> {
    let function_selector: [u8; 4] = tx.input()[0..4].try_into()?;

    if function_selector == BitcoinLightClientContract::setBlockInfoCall::SELECTOR {
        let l1_block_hash: [u8; 32] = tx.input()[4..36].try_into()?;
        let da_block = da_service
            .get_block_by_hash(l1_block_hash.into())
            .await
            .map_err(|e| anyhow!(e))?;
        let short_header_proof: <<Da as DaService>::Spec as DaSpec>::ShortHeaderProof =
            Da::block_to_short_header_proof(da_block.clone());
        ledger_db
            .put_short_header_proof_by_l1_hash(
                &l1_block_hash,
                borsh::to_vec(&short_header_proof).expect("Should serialize short header proof"),
            )
            .expect("Should save short header proof to ledger db");
        return Ok(Some(da_block));
    } else if function_selector == BitcoinLightClientContract::initializeBlockNumberCall::SELECTOR {
        // Also save the short header proof for the initial l1 block
        let block_num_be_bytes: [u8; 32] = tx.input()[4..36].try_into()?;
        let block_num = U256::from_be_bytes(block_num_be_bytes);
        let l1_block_hash = da_service.get_block_at(block_num.to()).await.unwrap();
        let short_header_proof: <<Da as DaService>::Spec as DaSpec>::ShortHeaderProof =
            Da::block_to_short_header_proof(l1_block_hash.clone());
        ledger_db
            .put_short_header_proof_by_l1_hash(
                &l1_block_hash.hash(),
                borsh::to_vec(&short_header_proof).expect("Should serialize short header proof"),
            )
            .expect("Should save short header proof to ledger db");
    }

    Ok(None)
}

/// This does not check for misplaced sys txs etc. but they will be rejected by the stf if they are misplaced when the transactions are run
pub async fn pre_fork2_decode_sov_tx_and_update_short_header_proofs<
    Da: DaService,
    DB: SharedLedgerOps,
>(
    l2_block_response: &SoftConfirmationResponse,
    ledger_db: &DB,
    da_service: Arc<Da>,
) -> anyhow::Result<Option<Da::FilteredBlock>> {
    let mut new_da_block = None;
    if let Some(txs) = &l2_block_response.txs {
        for tx in txs {
            let tx = &tx.tx;
            let tx = PreFork2Transaction::<DefaultContext>::try_from_slice(tx)
                .expect("Should deserialize transaction");
            let runtime_msg = tx.runtime_msg;
            if runtime_msg[0] == 1 {
                // This is evm call message
                let evm_call_message =
                    EvmCallMessage::try_from_slice(&runtime_msg[1..]).expect("Should be the tx");
                let evm_txs = evm_call_message.txs;
                for tx in evm_txs {
                    let tx = TransactionSignedEcRecovered::try_from(tx)
                        .expect("Should deserialize evm transaction");
                    if tx.signer() == SYSTEM_SIGNER {
                        new_da_block = update_short_header_proof_from_sys_tx(
                            &tx,
                            ledger_db,
                            da_service.clone(),
                        )
                        .await?;
                    }
                }
            }
        }
    }
    Ok(new_da_block)
}

pub async fn collect_system_txs(
    l2_block_response: &SoftConfirmationResponse,
) -> Vec<TransactionSignedEcRecovered> {
    let mut system_txs = Vec::new();
    if let Some(txs) = &l2_block_response.txs {
        for tx in txs {
            let tx = &tx.tx;
            let tx = PreFork2Transaction::<DefaultContext>::try_from_slice(tx)
                .expect("Should deserialize transaction");
            let runtime_msg = tx.runtime_msg;
            if runtime_msg[0] == 1 {
                // This is evm call message
                let evm_call_message =
                    EvmCallMessage::try_from_slice(&runtime_msg[1..]).expect("Should be the tx");
                let evm_txs = evm_call_message.txs;
                for tx in evm_txs {
                    let tx = TransactionSignedEcRecovered::try_from(tx)
                        .expect("Should deserialize evm transaction");
                    if tx.signer() == SYSTEM_SIGNER {
                        system_txs.push(tx);
                    }
                }
            }
        }
    }
    system_txs
}

pub fn collect_user_txs(
    l2_block_response: &SoftConfirmationResponse,
) -> Vec<TransactionSignedEcRecovered> {
    let mut user_txs = Vec::new();
    if let Some(txs) = &l2_block_response.txs {
        for tx in txs {
            let tx = &tx.tx;
            let tx = PreFork2Transaction::<DefaultContext>::try_from_slice(tx)
                .expect("Should deserialize transaction");
            let runtime_msg = tx.runtime_msg;
            if runtime_msg[0] == 1 {
                // This is evm call message
                let evm_call_message =
                    EvmCallMessage::try_from_slice(&runtime_msg[1..]).expect("Should be the tx");
                let evm_txs = evm_call_message.txs;
                for tx in evm_txs {
                    let tx = TransactionSignedEcRecovered::try_from(tx)
                        .expect("Should deserialize evm transaction");
                    if tx.signer() != SYSTEM_SIGNER {
                        user_txs.push(tx);
                    }
                }
            }
        }
    }
    user_txs
}
