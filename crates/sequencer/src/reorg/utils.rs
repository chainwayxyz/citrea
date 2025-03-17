use borsh::BorshDeserialize;
use citrea_evm::{CallMessage as EvmCallMessage, SYSTEM_SIGNER};
use citrea_stf::runtime::DefaultContext;
use reth_primitives::TransactionSignedEcRecovered;

use super::types::{PreFork2Transaction, SoftConfirmationResponse};

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
