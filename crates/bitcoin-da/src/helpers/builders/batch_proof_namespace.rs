use core::result::Result::Ok;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Instant;

use bitcoin::blockdata::opcodes::all::{OP_ENDIF, OP_IF};
use bitcoin::blockdata::opcodes::OP_FALSE;
use bitcoin::blockdata::script;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, TweakedPublicKey, UntweakedKeypair};
use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_NIP};
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Address, Amount, Network, Transaction};
use metrics::histogram;
use serde::Serialize;
use tracing::{instrument, trace, warn};

use super::{
    build_commit_transaction, build_reveal_transaction, build_taproot, build_witness,
    get_size_reveal, sign_blob_with_private_key, update_witness, TransactionKindBatchProof,
    TxListWithReveal, TxWithId,
};
use crate::spec::utxo::UTXO;
use crate::{REVEAL_OUTPUT_AMOUNT, REVEAL_OUTPUT_THRESHOLD};

/// This is a list of batch proof tx we need to send to DA (only SequencerCommitment for now)
#[derive(Serialize)]
pub(crate) struct BatchProvingTxs {
    pub(crate) commit: Transaction, // unsigned
    pub(crate) reveal: TxWithId,
}

impl TxListWithReveal for BatchProvingTxs {
    fn write_to_file(&self, mut path: PathBuf) -> Result<(), anyhow::Error> {
        path.push(format!(
            "batch_proof_inscription_with_reveal_id_{}.txs",
            self.reveal.id
        ));

        let file = File::create(path)?;
        let mut writer = BufWriter::new(&file);
        writer.write_all(&serialize(&self.commit))?;
        writer.write_all(&serialize(&self.reveal.tx))?;
        writer.flush()?;
        Ok(())
    }
}

// TODO: parametrize hardness
// so tests are easier
// Creates the batch proof transactions (commit and reveal)
#[allow(clippy::too_many_arguments)]
#[instrument(level = "trace", skip_all, err)]
pub fn create_seqcommitment_transactions(
    body: Vec<u8>,
    da_private_key: SecretKey,
    prev_utxo: Option<UTXO>,
    utxos: Vec<UTXO>,
    change_address: Address,
    commit_fee_rate: u64,
    reveal_fee_rate: u64,
    network: Network,
    reveal_tx_prefix: Vec<u8>,
) -> Result<BatchProvingTxs, anyhow::Error> {
    create_batchproof_type_0(
        body,
        &da_private_key,
        prev_utxo,
        utxos,
        change_address,
        commit_fee_rate,
        reveal_fee_rate,
        network,
        &reveal_tx_prefix,
    )
}

// Creates the batch proof transactions Type 0 - BatchProvingTxs - SequencerCommitment
#[allow(clippy::too_many_arguments)]
#[instrument(level = "trace", skip_all, err)]
pub fn create_batchproof_type_0(
    body: Vec<u8>,
    da_private_key: &SecretKey,
    prev_utxo: Option<UTXO>,
    utxos: Vec<UTXO>,
    change_address: Address,
    commit_fee_rate: u64,
    reveal_fee_rate: u64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> Result<BatchProvingTxs, anyhow::Error> {
    debug_assert!(
        body.len() < 520,
        "The body of a serialized sequencer commitment exceeds 520 bytes"
    );
    // Create reveal key
    let secp256k1 = Secp256k1::new();
    let key_pair = UntweakedKeypair::new(&secp256k1, &mut rand::thread_rng());
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let kind = TransactionKindBatchProof::SequencerCommitment;
    let kind_bytes = kind.to_bytes();

    // sign the body for authentication of the sequencer
    let (signature, signer_public_key) = sign_blob_with_private_key(&body, da_private_key);

    // start creating inscription content
    let reveal_script_builder = script::Builder::new()
        .push_x_only_key(&public_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(PushBytesBuf::try_from(kind_bytes).expect("Cannot push header"))
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(PushBytesBuf::try_from(signature).expect("Cannot push signature"))
        .push_slice(
            PushBytesBuf::try_from(signer_public_key).expect("Cannot push sequencer public key"),
        )
        .push_slice(PushBytesBuf::try_from(body).expect("Cannot push sequencer commitment"))
        .push_opcode(OP_ENDIF);

    let start = Instant::now();
    // Start loop to find a 'nonce' i.e. random number that makes the reveal tx hash starting with zeros given length
    let mut nonce: i64 = 16; // skip the first digits to avoid OP_PUSHNUM_X
    loop {
        if nonce % 1000 == 0 {
            trace!(nonce, "Trying to find commit & reveal nonce");
            if nonce > 16384 {
                warn!("Too many iterations finding nonce");
            }
        }
        let utxos = utxos.clone();
        let change_address = change_address.clone();
        // ownerships are moved to the loop
        let mut reveal_script_builder = reveal_script_builder.clone();

        // push nonce
        reveal_script_builder = reveal_script_builder
            .push_slice(nonce.to_le_bytes())
            // drop the second item, bc there is a big chance it's 0 (tx kind) and nonce is >= 16
            .push_opcode(OP_NIP);

        // finalize reveal script
        let reveal_script = reveal_script_builder.into_script();

        let (control_block, merkle_root, tapscript_hash) =
            build_taproot(&reveal_script, public_key, &secp256k1);

        // create commit tx address
        let commit_tx_address = Address::p2tr(&secp256k1, public_key, merkle_root, network);

        let reveal_value = REVEAL_OUTPUT_AMOUNT;
        let fee = get_size_reveal(
            change_address.script_pubkey(),
            reveal_value,
            &reveal_script,
            &control_block,
        ) as u64
            * reveal_fee_rate;
        let reveal_input_value = fee + reveal_value + REVEAL_OUTPUT_THRESHOLD;

        // build commit tx
        // we don't need leftover_utxos because they will be requested from bitcoind next call
        let (mut unsigned_commit_tx, _leftover_utxos) = build_commit_transaction(
            prev_utxo.clone(),
            utxos,
            commit_tx_address.clone(),
            change_address.clone(),
            reveal_input_value,
            commit_fee_rate,
        )?;

        let output_to_reveal = unsigned_commit_tx.output[0].clone();

        let mut reveal_tx = build_reveal_transaction(
            output_to_reveal.clone(),
            unsigned_commit_tx.compute_txid(),
            0,
            change_address,
            reveal_value + REVEAL_OUTPUT_THRESHOLD,
            reveal_fee_rate,
            &reveal_script,
            &control_block,
        )?;

        build_witness(
            &unsigned_commit_tx,
            &mut reveal_tx,
            tapscript_hash,
            reveal_script,
            control_block,
            &key_pair,
            &secp256k1,
        );

        let min_commit_value = Amount::from_sat(fee + reveal_value);
        while unsigned_commit_tx.output[0].value >= min_commit_value {
            // tracing::info!("reveal output: {}", reveal_tx.output[0].value);
            let reveal_wtxid = reveal_tx.compute_wtxid();
            let reveal_hash = reveal_wtxid.as_raw_hash().to_byte_array();
            // check if first N bytes equal to the given prefix
            if reveal_hash.starts_with(reveal_tx_prefix) {
                // check if inscription locked to the correct address
                let recovery_key_pair = key_pair.tap_tweak(&secp256k1, merkle_root);
                let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
                assert_eq!(
                    Address::p2tr_tweaked(
                        TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
                        network,
                    ),
                    commit_tx_address
                );

                histogram!("mine_da_transaction").record(
                    Instant::now()
                        .saturating_duration_since(start)
                        .as_secs_f64(),
                );

                return Ok(BatchProvingTxs {
                    commit: unsigned_commit_tx,
                    reveal: TxWithId {
                        id: reveal_tx.compute_txid(),
                        tx: reveal_tx,
                    },
                });
            } else {
                unsigned_commit_tx.output[0].value -= Amount::ONE_SAT;
                unsigned_commit_tx.output[1].value += Amount::ONE_SAT;
                reveal_tx.output[0].value -= Amount::ONE_SAT;
                reveal_tx.input[0].previous_output.txid = unsigned_commit_tx.compute_txid();
                update_witness(
                    &unsigned_commit_tx,
                    &mut reveal_tx,
                    tapscript_hash,
                    &key_pair,
                    &secp256k1,
                );
            }
        }

        nonce += 1;
    }
}
