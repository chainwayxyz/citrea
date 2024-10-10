use core::result::Result::Ok;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use bitcoin::blockdata::opcodes::all::{OP_ENDIF, OP_IF};
use bitcoin::blockdata::opcodes::OP_FALSE;
use bitcoin::blockdata::script;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, TweakedPublicKey, UntweakedKeypair};
use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_NIP};
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{self, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{Address, Network, Transaction};
use serde::Serialize;
use tracing::{instrument, trace, warn};

use super::{TransactionKindBatchProof, TxListWithReveal, TxWithId};
use crate::helpers::builders::{
    build_commit_transaction, build_reveal_transaction, get_size_reveal, sign_blob_with_private_key,
};
use crate::spec::utxo::UTXO;

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
pub async fn create_seqcommitment_transactions(
    body: Vec<u8>,
    da_private_key: SecretKey,
    prev_utxo: Option<UTXO>,
    utxos: Vec<UTXO>,
    change_address: Address,
    reveal_value: u64,
    commit_fee_rate: u64,
    reveal_fee_rate: u64,
    network: Network,
    reveal_tx_prefix: Vec<u8>,
) -> Result<BatchProvingTxs, anyhow::Error> {
    // Since this is CPU bound work, we use spawn_blocking
    // to release the tokio runtime execution
    tokio::task::spawn_blocking(move || {
        create_batchproof_type_0(
            body,
            &da_private_key,
            prev_utxo,
            utxos,
            change_address,
            reveal_value,
            commit_fee_rate,
            reveal_fee_rate,
            network,
            &reveal_tx_prefix,
        )
    })
    .await
    .expect("No JoinErrors")
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
    reveal_value: u64,
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

    println!("reveal_script_builder: {:?}", reveal_script_builder);
    // Start loop to find a 'nonce' i.e. random number that makes the reveal tx hash starting with zeros given length
    let mut nonce: i64 = 16; // skip the first digits to avoid OP_PUSHNUM_X
    loop {
        if nonce % 10000 == 0 {
            trace!(nonce, "Trying to find commit & reveal nonce");
            if nonce > 65536 {
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

        // create spend info for tapscript
        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone())
            .expect("Cannot add reveal script to taptree")
            .finalize(&secp256k1, public_key)
            .expect("Cannot finalize taptree");

        // create control block for tapscript
        let control_block = taproot_spend_info
            .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
            .expect("Cannot create control block");

        // create commit tx address
        let commit_tx_address = Address::p2tr(
            &secp256k1,
            public_key,
            taproot_spend_info.merkle_root(),
            network,
        );

        let reveal_input_value = get_size_reveal(
            change_address.script_pubkey(),
            reveal_value,
            &reveal_script,
            &control_block,
        ) as u64
            * reveal_fee_rate
            + reveal_value;

        // build commit tx
        // we don't need leftover_utxos because they will be requested from bitcoind next call
        let (unsigned_commit_tx, _leftover_utxos) = build_commit_transaction(
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
            reveal_value,
            reveal_fee_rate,
            &reveal_script,
            &control_block,
        )?;

        // start signing reveal tx
        let mut sighash_cache = SighashCache::new(&mut reveal_tx);

        // create data to sign
        let signature_hash = sighash_cache
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[output_to_reveal]),
                TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
                bitcoin::sighash::TapSighashType::Default,
            )
            .expect("Cannot create hash for signature");

        // sign reveal tx data
        let signature = secp256k1.sign_schnorr_with_rng(
            &secp256k1::Message::from_digest_slice(signature_hash.as_byte_array())
                .expect("should be cryptographically secure hash"),
            &key_pair,
            &mut rand::thread_rng(),
        );

        // add signature to witness and finalize reveal tx
        let witness = sighash_cache.witness_mut(0).unwrap();
        witness.push(signature.as_ref());
        witness.push(reveal_script);
        witness.push(&control_block.serialize());

        let reveal_wtxid = reveal_tx.compute_wtxid();
        let reveal_hash = reveal_wtxid.as_raw_hash().to_byte_array();

        // check if first N bytes equal to the given prefix
        if reveal_hash.starts_with(reveal_tx_prefix) {
            // check if inscription locked to the correct address
            let recovery_key_pair =
                key_pair.tap_tweak(&secp256k1, taproot_spend_info.merkle_root());
            let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
            assert_eq!(
                Address::p2tr_tweaked(
                    TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
                    network,
                ),
                commit_tx_address
            );

            return Ok(BatchProvingTxs {
                commit: unsigned_commit_tx,
                reveal: TxWithId {
                    id: reveal_tx.compute_txid(),
                    tx: reveal_tx,
                },
            });
        }

        nonce += 1;
    }
}
