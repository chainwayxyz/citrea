use std::collections::HashMap;
use std::sync::Arc;

use alloy_consensus::transaction::Transaction as _;
use alloy_sol_types::SolCall;
use anyhow::{anyhow, Context as _};
use borsh::BorshDeserialize;
use citrea_evm::system_contracts::{BitcoinLightClientContract, BridgeContract};
use citrea_evm::{CallMessage as EvmCallMessage, SYSTEM_SIGNER};
use citrea_primitives::EMPTY_TX_ROOT;
use reth_primitives::{Recovered, TransactionSigned};
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_db::ledger_db::SharedLedgerOps;
use sov_modules_api::{Context, DaSpec, Spec};
use sov_rollup_interface::rpc::block::L2BlockResponse;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::StateDiff;
use sov_rollup_interface::transaction::Transaction;

pub fn merge_state_diffs(old_diff: StateDiff, new_diff: StateDiff) -> StateDiff {
    let mut new_diff_map: HashMap<Arc<[u8]>, Option<Arc<[u8]>>> = HashMap::from_iter(old_diff);

    new_diff_map.extend(new_diff);
    new_diff_map.into_iter().collect()
}

pub fn check_l2_block_exists<DB: SharedLedgerOps>(ledger_db: &DB, l2_height: u64) -> bool {
    let Some(head_l2_height) = ledger_db
        .get_head_l2_block_height()
        .expect("Ledger db read must not fail")
    else {
        return false;
    };

    head_l2_height >= l2_height
}

pub fn compute_tx_hashes<C: Context>(txs: &[Transaction], _current_spec: SpecId) -> Vec<[u8; 32]> {
    txs.iter()
        .map(|tx| tx.compute_digest::<<C as Spec>::Hasher>().into())
        .collect()
}

pub fn compute_tx_merkle_root(tx_hashes: &[[u8; 32]]) -> anyhow::Result<[u8; 32]> {
    if tx_hashes.is_empty() {
        return Ok(EMPTY_TX_ROOT);
    }

    MerkleTree::<Sha256>::from_leaves(tx_hashes)
        .root()
        .context("Couldn't compute merkle root")
}

async fn update_short_header_proof_from_sys_tx<Da: DaService, DB: SharedLedgerOps>(
    tx: &Recovered<TransactionSigned>,
    ledger_db: &DB,
    da_service: Arc<Da>,
) -> anyhow::Result<()> {
    let function_selector: [u8; 4] = tx
        .input()
        .get(0..4)
        .ok_or(anyhow!("System tx should have func. selector"))?
        .try_into()?;

    match function_selector {
        BitcoinLightClientContract::initializeBlockNumberCall::SELECTOR => {
            tracing::info!("Initialize Bitcoin Light Client contract system tx found inside block");
        }
        BitcoinLightClientContract::setBlockInfoCall::SELECTOR => {
            tracing::info!("setBlockInfo system tx found inside block");

            let l1_block_hash: [u8; 32] = tx
                .input()
                .get(4..36)
                .ok_or(anyhow!("Set block info call should have 32 bytes input"))?
                .try_into()?;
            // Check if shp exists for this l1 block hash
            if ledger_db
                .get_short_header_proof_by_l1_hash(&l1_block_hash)?
                .is_some()
            {
                return Ok(());
            }
            let da_block = da_service
                .get_block_by_hash(l1_block_hash.into())
                .await
                .map_err(|e| anyhow!(e))?;
            let short_header_proof: <<Da as DaService>::Spec as DaSpec>::ShortHeaderProof =
                Da::block_to_short_header_proof(da_block);
            ledger_db
                .put_short_header_proof_by_l1_hash(
                    &l1_block_hash,
                    borsh::to_vec(&short_header_proof)
                        .expect("Should serialize short header proof"),
                )
                .expect("Should save short header proof to ledger db");
        }
        BridgeContract::initializeCall::SELECTOR => {
            tracing::info!("Initialize Bridge contract system tx found inside block");
        }
        BridgeContract::depositCall::SELECTOR => {
            tracing::info!("Deposit system tx found inside block");
        }
        _ => {
            return Err(anyhow!("Invalid system tx"));
        }
    }

    Ok(())
}

/// This does not check for misplaced sys txs etc. but they will be rejected by the stf if they are misplaced when the transactions are run
pub async fn decode_sov_tx_and_update_short_header_proofs<Da: DaService, DB: SharedLedgerOps>(
    l2_block_response: &L2BlockResponse,
    ledger_db: &DB,
    da_service: Arc<Da>,
) -> anyhow::Result<()> {
    for tx in &l2_block_response.txs {
        let tx = &tx.tx;
        let tx = Transaction::try_from_slice(tx).context("Should deserialize transaction")?;
        let runtime_msg = tx.runtime_msg();

        if runtime_msg.len() < 2 {
            return Err(anyhow!("Invalid runtime message"));
        }

        if runtime_msg[0] == 1 {
            // This is evm call message
            let evm_call_message = EvmCallMessage::try_from_slice(&runtime_msg[1..])
                .context("Should deserialize evm call message")?;
            let evm_txs = evm_call_message.txs;
            for tx in evm_txs {
                let tx = Recovered::try_from(tx)
                    .map_err(|_| anyhow!("Should be able to recover evm tx"))?;
                if tx.signer() == SYSTEM_SIGNER {
                    update_short_header_proof_from_sys_tx(&tx, ledger_db, da_service.clone())
                        .await?;
                } else {
                    // if we have a different sender, we can skip decoding other txs
                    // as the sys-tx can only be in the beginning of the block check is also done in evm
                    // we don't need to check for that here.
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}
