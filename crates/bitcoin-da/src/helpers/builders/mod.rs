pub mod batch_proof_namespace;
pub mod light_client_proof_namespace;

#[cfg(test)]
mod tests;

use core::fmt;
use core::result::Result::Ok;
use std::collections::HashSet;
use std::path::PathBuf;

use anyhow::anyhow;
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::script;
use bitcoin::hashes::Hash;
use bitcoin::key::constants::SCHNORR_SIGNATURE_SIZE;
use bitcoin::secp256k1::{self, All, Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder};
use bitcoin::{
    Address, Amount, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapNodeHash, Transaction, TxIn,
    TxOut, Txid, Witness, XOnlyPublicKey,
};
use serde::Serialize;
use tracing::{instrument, trace, warn};

use super::{calculate_sha256, TransactionKindBatchProof, TransactionKindLightClient};
use crate::spec::utxo::UTXO;
use crate::REVEAL_OUTPUT_AMOUNT;

/// Both transaction and its hash
#[derive(Clone, Serialize)]
pub struct TxWithId {
    /// ID (hash)
    pub id: Txid,
    /// Transaction
    pub tx: Transaction,
}

impl fmt::Debug for TxWithId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TxWithId")
            .field("id", &self.id)
            .field("tx", &"...")
            .finish()
    }
}

// To dump raw da txs into file to recover from a sequencer crash
pub(crate) trait TxListWithReveal: Serialize {
    fn write_to_file(&self, dir: PathBuf) -> Result<(), anyhow::Error>;
}

/// Return (tx, leftover_utxos)
/// Includes an indirect change of at least 546 sat
#[instrument(level = "trace", skip(utxos), err)]
fn build_commit_transaction(
    prev_utxo: Option<UTXO>, // reuse outputs to add commit tx order
    mut utxos: Vec<UTXO>,
    recipient: Address,
    change_address: Address,
    output_value: u64,
    fee_rate: u64,
) -> Result<(Transaction, Vec<UTXO>), anyhow::Error> {
    // Non-dust change - is a minimal change to make change non_dust
    let non_dust_change = 546;
    // get single input single output transaction size
    let size = get_size_commit(
        &[TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0; 32]),
                vout: 0,
            },
            script_sig: script::Builder::new().into_script(),
            witness: Witness::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        }],
        &[
            TxOut {
                script_pubkey: recipient.clone().script_pubkey(),
                value: Amount::from_sat(output_value),
            },
            TxOut {
                script_pubkey: change_address.script_pubkey(),
                value: Amount::from_sat(non_dust_change),
            },
        ],
    );

    if let Some(req_utxo) = &prev_utxo {
        // if we don't do this, then we might end up using the required utxo twice
        // which would yield an invalid transaction
        // however using a different txo from the same tx is fine.
        utxos.retain(|utxo| !(utxo.vout == req_utxo.vout && utxo.tx_id == req_utxo.tx_id));
    }

    let mut iteration = 0;
    let mut last_size = size;

    let (leftover_utxos, tx) = loop {
        if iteration % 10 == 0 {
            trace!(iteration, "Trying to find commitment size");
            if iteration > 100 {
                warn!("Too many iterations choosing UTXOs");
            }
        }
        let fee = (last_size as u64) * fee_rate;

        let input_total = output_value + fee + non_dust_change;

        let (chosen_utxos, sum, leftover_utxos) =
            choose_utxos(prev_utxo.clone(), &utxos, input_total)?;
        let has_change = (sum - input_total) >= REVEAL_OUTPUT_AMOUNT;
        let direct_return = !has_change;

        let outputs = if !has_change {
            vec![
                TxOut {
                    value: Amount::from_sat(output_value),
                    script_pubkey: recipient.script_pubkey(),
                },
                TxOut {
                    script_pubkey: change_address.script_pubkey(),
                    value: Amount::from_sat(non_dust_change),
                },
            ]
        } else {
            vec![
                TxOut {
                    value: Amount::from_sat(output_value),
                    script_pubkey: recipient.script_pubkey(),
                },
                TxOut {
                    value: Amount::from_sat(sum - input_total + non_dust_change),
                    script_pubkey: change_address.script_pubkey(),
                },
            ]
        };

        let inputs: Vec<_> = chosen_utxos
            .iter()
            .map(|u| TxIn {
                previous_output: OutPoint {
                    txid: u.tx_id,
                    vout: u.vout,
                },
                script_sig: script::Builder::new().into_script(),
                witness: Witness::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            })
            .collect();

        if direct_return {
            break (
                leftover_utxos,
                Transaction {
                    lock_time: LockTime::ZERO,
                    version: bitcoin::transaction::Version(2),
                    input: inputs,
                    output: outputs,
                },
            );
        }

        let size = get_size_commit(&inputs, &outputs);

        if size == last_size {
            break (
                leftover_utxos,
                Transaction {
                    lock_time: LockTime::ZERO,
                    version: bitcoin::transaction::Version(2),
                    input: inputs,
                    output: outputs,
                },
            );
        }

        last_size = size;
        iteration += 1;
    };

    Ok((tx, leftover_utxos))
}

#[allow(clippy::too_many_arguments)]
fn build_reveal_transaction(
    input_utxo: TxOut,
    input_txid: Txid,
    input_vout: u32,
    recipient: Address,
    output_value: u64,
    fee_rate: u64,
    reveal_script: &ScriptBuf,
    control_block: &ControlBlock,
) -> Result<Transaction, anyhow::Error> {
    let outputs: Vec<TxOut> = vec![TxOut {
        value: Amount::from_sat(output_value),
        script_pubkey: recipient.script_pubkey(),
    }];

    let inputs = vec![TxIn {
        previous_output: OutPoint {
            txid: input_txid,
            vout: input_vout,
        },
        script_sig: script::Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
    }];

    // sanity check
    // the reveal input should already hvae calculated the reveal output size + reveal fee
    let size = get_size_reveal(
        recipient.script_pubkey(),
        output_value,
        reveal_script,
        control_block,
    );

    let fee = (size as u64) * fee_rate;

    let input_total = output_value + fee;

    if input_utxo.value < Amount::from_sat(REVEAL_OUTPUT_AMOUNT)
        || input_utxo.value < Amount::from_sat(input_total)
    {
        return Err(anyhow::anyhow!("input UTXO not big enough"));
    }

    let tx = Transaction {
        lock_time: LockTime::ZERO,
        version: bitcoin::transaction::Version(2),
        input: inputs,
        output: outputs,
    };

    Ok(tx)
}

fn build_taproot(
    reveal_script: &ScriptBuf,
    public_key: XOnlyPublicKey,
    secp256k1: &Secp256k1<All>,
) -> (ControlBlock, Option<TapNodeHash>, TapLeafHash) {
    // create spend info for tapscript
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .expect("Cannot add reveal script to taptree")
        .finalize(secp256k1, public_key)
        .expect("Cannot finalize taptree");

    // create tapleaf hash
    let tapleaf_hash = TapLeafHash::from_script(reveal_script, LeafVersion::TapScript);

    // create control block for tapscript
    let control_block = taproot_spend_info
        .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
        .expect("Cannot create control block");

    (
        control_block,
        taproot_spend_info.merkle_root(),
        tapleaf_hash,
    )
}

fn build_witness(
    commit_tx: &Transaction,
    reveal_tx: &mut Transaction,
    tapscript_hash: TapLeafHash,
    reveal_script: ScriptBuf,
    control_block: ControlBlock,
    key_pair: &Keypair,
    secp256k1: &Secp256k1<All>,
) {
    // start signing reveal tx
    let mut sighash_cache = SighashCache::new(reveal_tx);

    // create data to sign
    let signature_hash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[&commit_tx.output[0]]),
            tapscript_hash,
            bitcoin::sighash::TapSighashType::Default,
        )
        .expect("Cannot create hash for signature");

    // sign reveal tx data
    let signature = secp256k1.sign_schnorr_with_rng(
        &Message::from_digest_slice(signature_hash.as_byte_array())
            .expect("should be cryptographically secure hash"),
        key_pair,
        &mut rand::thread_rng(),
    );

    // add signature to witness and finalize reveal tx
    let witness = sighash_cache.witness_mut(0).unwrap();
    witness.clear();
    witness.push(signature.as_ref());
    witness.push(reveal_script);
    witness.push(&control_block.serialize());
}

fn update_witness(
    commit_tx: &Transaction,
    reveal_tx: &mut Transaction,
    tapscript_hash: TapLeafHash,
    key_pair: &Keypair,
    secp256k1: &Secp256k1<All>,
) {
    // start signing reveal tx
    let mut sighash_cache = SighashCache::new(reveal_tx);

    // create data to sign
    let signature_hash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[&commit_tx.output[0]]),
            tapscript_hash,
            bitcoin::sighash::TapSighashType::Default,
        )
        .expect("Cannot create hash for signature");

    // sign reveal tx data
    let signature = secp256k1.sign_schnorr_with_rng(
        &Message::from_digest_slice(signature_hash.as_byte_array())
            .expect("should be cryptographically secure hash"),
        key_pair,
        &mut rand::thread_rng(),
    );

    // add signature to witness and finalize reveal tx
    let witness = sighash_cache.witness_mut(0).unwrap();

    let reveal_script = witness.nth(1).unwrap();
    let control_block = witness.nth(2).unwrap();

    let mut new_witness = Witness::new();
    new_witness.push(signature.as_ref());
    new_witness.push(reveal_script);
    new_witness.push(control_block);

    *witness = new_witness;
}

fn get_size_commit(inputs: &[TxIn], outputs: &[TxOut]) -> usize {
    let mut tx = Transaction {
        input: inputs.to_vec(),
        output: outputs.to_vec(),
        lock_time: LockTime::ZERO,
        version: bitcoin::transaction::Version(2),
    };

    // TODO: adjust size of sig. for different types of addresses
    for i in 0..tx.input.len() {
        tx.input[i].witness.push(&vec![0; SCHNORR_SIGNATURE_SIZE]);
    }

    tx.vsize()
}

/// Assumes one input one output inscription transaction
fn get_size_reveal(
    recipient: ScriptBuf,
    output_amount: u64,
    script: &ScriptBuf,
    control_block: &ControlBlock,
) -> usize {
    let mut witness = Witness::new();

    witness.push(vec![0; SCHNORR_SIGNATURE_SIZE]);
    witness.push(script);
    witness.push(control_block.serialize());

    let inputs = vec![TxIn {
        previous_output: OutPoint {
            txid: Txid::from_byte_array([0; 32]),
            vout: 0,
        },
        script_sig: script::Builder::new().into_script(),
        witness,
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
    }];

    let outputs = vec![TxOut {
        value: Amount::from_sat(output_amount),
        script_pubkey: recipient,
    }];

    let tx = Transaction {
        input: inputs.to_owned(),
        output: outputs.to_owned(),
        lock_time: LockTime::ZERO,
        version: bitcoin::transaction::Version(2),
    };

    tx.vsize()
}

/// Return (chosen_utxos, sum(chosen.amount), leftover_utxos)
fn choose_utxos(
    required_utxo: Option<UTXO>,
    utxos: &[UTXO],
    mut amount: u64,
) -> Result<(Vec<UTXO>, u64, Vec<UTXO>), anyhow::Error> {
    let mut chosen_utxos = vec![];
    let mut sum = 0;

    // First include a required utxo
    if let Some(required) = required_utxo {
        let req_amount = required.amount;
        chosen_utxos.push(required);
        sum += req_amount;
    }
    if sum >= amount {
        return Ok((chosen_utxos, sum, utxos.to_vec()));
    } else {
        amount -= sum;
    }

    let mut bigger_utxos: Vec<&UTXO> = utxos.iter().filter(|utxo| utxo.amount >= amount).collect();

    if !bigger_utxos.is_empty() {
        // sort vec by amount (small first)
        bigger_utxos.sort_by(|a, b| a.amount.cmp(&b.amount));

        // single utxo will be enough
        // so return the transaction
        let utxo = bigger_utxos[0];
        sum += utxo.amount;
        chosen_utxos.push(utxo.clone());
    } else {
        let mut smaller_utxos: Vec<&UTXO> =
            utxos.iter().filter(|utxo| utxo.amount < amount).collect();

        // sort vec by amount (large first)
        smaller_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

        for utxo in smaller_utxos {
            sum += utxo.amount;
            chosen_utxos.push(utxo.clone());

            if sum >= amount {
                break;
            }
        }

        if sum < amount {
            return Err(anyhow!("not enough UTXOs"));
        }
    }

    let input_set: HashSet<_> = utxos.iter().collect();
    let chosen_set: HashSet<_> = chosen_utxos.iter().collect();
    let leftovers_set = input_set.difference(&chosen_set);
    let leftovers: Vec<_> = leftovers_set.copied().cloned().collect();

    Ok((chosen_utxos, sum, leftovers))
}

/// Signs a message with a private key
/// Returns (signature, public_key)
pub fn sign_blob_with_private_key(blob: &[u8], private_key: &SecretKey) -> (Vec<u8>, Vec<u8>) {
    let message = calculate_sha256(blob);
    let secp = Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, private_key);
    let msg = secp256k1::Message::from_digest(message);
    let sig = secp.sign_ecdsa(&msg, private_key);
    (
        sig.serialize_compact().to_vec(),
        public_key.serialize().to_vec(),
    )
}
