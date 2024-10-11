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
use bitcoin::secp256k1::{Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Address, Network, Transaction};
use citrea_primitives::MAX_TXBODY_SIZE;
use serde::Serialize;
use tracing::{instrument, trace, warn};

use super::{
    build_commit_transaction, build_reveal_transaction, build_taproot, build_witness,
    get_size_reveal, sign_blob_with_private_key, TransactionKindLightClient, TxListWithReveal,
    TxWithId,
};
use crate::spec::utxo::UTXO;

/// This is a list of light client tx we need to send to DA
#[derive(Serialize)]
pub(crate) enum LightClientTxs {
    Complete {
        commit: Transaction, // unsigned
        reveal: TxWithId,
    },
    Chunked {
        commit_chunks: Vec<Transaction>, // unsigned
        reveal_chunks: Vec<Transaction>,
        commit: Transaction, // unsigned
        reveal: TxWithId,
    },
}

impl TxListWithReveal for LightClientTxs {
    fn write_to_file(&self, mut path: PathBuf) -> Result<(), anyhow::Error> {
        match self {
            Self::Complete { commit, reveal } => {
                path.push(format!(
                    "complete_light_client_inscription_with_reveal_id_{}.txs",
                    reveal.id
                ));
                let file = File::create(path)?;
                let mut writer: BufWriter<&File> = BufWriter::new(&file);
                writer.write_all(&serialize(commit))?;
                writer.write_all(&serialize(&reveal.tx))?;
                writer.flush()?;
                Ok(())
            }
            Self::Chunked {
                commit_chunks,
                reveal_chunks,
                commit,
                reveal,
            } => {
                path.push(format!(
                    "chunked_light_client_inscription_with_reveal_id_{}.txs",
                    reveal.id
                ));
                let file = File::create(path)?;
                let mut writer = BufWriter::new(&file);
                for (commit_chunk, reveal_chunk) in commit_chunks.iter().zip(reveal_chunks.iter()) {
                    writer.write_all(&serialize(commit_chunk))?;
                    writer.write_all(&serialize(reveal_chunk))?;
                }
                writer.write_all(&serialize(commit))?;
                writer.write_all(&serialize(&reveal.tx))?;
                writer.flush()?;
                Ok(())
            }
        }
    }
}

// TODO: parametrize hardness
// so tests are easier
// Creates the light client transactions (commit and reveal)
#[allow(clippy::too_many_arguments)]
#[instrument(level = "trace", skip_all, err)]
pub fn create_zkproof_transactions(
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
) -> Result<LightClientTxs, anyhow::Error> {
    if body.len() < MAX_TXBODY_SIZE {
        create_inscription_type_0(
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
    } else {
        create_inscription_type_1(
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
    }
}

// TODO: parametrize hardness
// so tests are easier
// Creates the inscription transactions Type 0 - LightClientTxs::Complete
#[allow(clippy::too_many_arguments)]
#[instrument(level = "trace", skip_all, err)]
pub fn create_inscription_type_0(
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
) -> Result<LightClientTxs, anyhow::Error> {
    // Create reveal key
    let secp256k1 = Secp256k1::new();
    let key_pair = UntweakedKeypair::new(&secp256k1, &mut rand::thread_rng());
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let kind = TransactionKindLightClient::Complete;
    let kind_bytes = kind.to_bytes();

    // sign the body for authentication of the sequencer
    let (signature, signer_public_key) = sign_blob_with_private_key(&body, da_private_key);

    // start creating inscription content
    let mut reveal_script_builder = script::Builder::new()
        .push_x_only_key(&public_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(PushBytesBuf::try_from(kind_bytes).expect("Cannot push header"))
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(PushBytesBuf::try_from(signature).expect("Cannot push signature"))
        .push_slice(
            PushBytesBuf::try_from(signer_public_key).expect("Cannot push sequencer public key"),
        );
    // push body in chunks of 520 bytes
    for chunk in body.chunks(520) {
        reveal_script_builder = reveal_script_builder
            .push_slice(PushBytesBuf::try_from(chunk.to_vec()).expect("Cannot push body chunk"));
    }
    // push end if
    reveal_script_builder = reveal_script_builder.push_opcode(OP_ENDIF);

    // This envelope is not finished yet. The random number will be added later

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

        let (control_block, merkle_root) = build_taproot(&reveal_script, public_key, &secp256k1);

        // create commit tx address
        let commit_tx_address = Address::p2tr(&secp256k1, public_key, merkle_root, network);

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

        build_witness(
            &unsigned_commit_tx,
            &mut reveal_tx,
            reveal_script,
            control_block,
            &key_pair,
            &secp256k1,
        );

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

            return Ok(LightClientTxs::Complete {
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

// TODO: parametrize hardness
// so tests are easier
// Creates the inscription transactions Type 1 - LightClientTxs::Chunked
#[allow(clippy::too_many_arguments)]
#[instrument(level = "trace", skip_all, err)]
pub fn create_inscription_type_1(
    body: Vec<u8>,
    da_private_key: &SecretKey,
    mut prev_utxo: Option<UTXO>,
    mut utxos: Vec<UTXO>,
    change_address: Address,
    reveal_value: u64,
    commit_fee_rate: u64,
    reveal_fee_rate: u64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> Result<LightClientTxs, anyhow::Error> {
    // Create reveal key
    let secp256k1 = Secp256k1::new();
    let key_pair = UntweakedKeypair::new(&secp256k1, &mut rand::thread_rng());
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let mut commit_chunks: Vec<Transaction> = vec![];
    let mut reveal_chunks: Vec<Transaction> = vec![];

    for body in body.chunks(MAX_TXBODY_SIZE) {
        let kind = TransactionKindLightClient::ChunkedPart;
        let kind_bytes = kind.to_bytes();

        // start creating inscription content
        let mut reveal_script_builder = script::Builder::new()
            .push_x_only_key(&public_key)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(PushBytesBuf::try_from(kind_bytes).expect("Cannot push header"))
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF);
        // push body in chunks of 520 bytes
        for chunk in body.chunks(520) {
            reveal_script_builder = reveal_script_builder.push_slice(
                PushBytesBuf::try_from(chunk.to_vec()).expect("Cannot push body chunk"),
            );
        }
        // push end if
        let reveal_script = reveal_script_builder.push_opcode(OP_ENDIF).into_script();

        let (control_block, merkle_root) = build_taproot(&reveal_script, public_key, &secp256k1);

        // create commit tx address
        let commit_tx_address = Address::p2tr(&secp256k1, public_key, merkle_root, network);

        let reveal_input_value = get_size_reveal(
            change_address.script_pubkey(),
            reveal_value,
            &reveal_script,
            &control_block,
        ) as u64
            * reveal_fee_rate
            + reveal_value;

        // build commit tx
        let (unsigned_commit_tx, leftover_utxos) = build_commit_transaction(
            prev_utxo.clone(),
            utxos,
            commit_tx_address.clone(),
            change_address.clone(),
            reveal_input_value,
            commit_fee_rate,
        )?;

        let output_to_reveal = unsigned_commit_tx.output[0].clone();

        // If commit
        let commit_change = if unsigned_commit_tx.output.len() > 1 {
            Some(UTXO {
                tx_id: unsigned_commit_tx.compute_txid(),
                vout: 1,
                address: None,
                script_pubkey: unsigned_commit_tx.output[0].script_pubkey.to_hex_string(),
                amount: unsigned_commit_tx.output[1].value.to_sat(),
                confirmations: 0,
                spendable: true,
                solvable: true,
            })
        } else {
            None
        };

        let mut reveal_tx = build_reveal_transaction(
            output_to_reveal.clone(),
            unsigned_commit_tx.compute_txid(),
            0,
            change_address.clone(),
            reveal_value,
            reveal_fee_rate,
            &reveal_script,
            &control_block,
        )?;

        build_witness(
            &unsigned_commit_tx,
            &mut reveal_tx,
            reveal_script,
            control_block,
            &key_pair,
            &secp256k1,
        );

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

        // set prev utxo to last reveal tx[0] to chain txs in order
        prev_utxo = Some(UTXO {
            tx_id: reveal_tx.compute_txid(),
            vout: 0,
            script_pubkey: reveal_tx.output[0].script_pubkey.to_hex_string(),
            address: None,
            amount: reveal_tx.output[0].value.to_sat(),
            confirmations: 0,
            spendable: true,
            solvable: true,
        });

        commit_chunks.push(unsigned_commit_tx);
        reveal_chunks.push(reveal_tx);

        // Replace utxos with leftovers so we don't use prev utxos in next chunks
        utxos = leftover_utxos;
        if let Some(change) = commit_change {
            utxos.push(change);
        }
    }

    let reveal_tx_ids: Vec<_> = reveal_chunks
        .iter()
        .map(|tx| tx.compute_txid().to_byte_array())
        .collect();

    // To sign the list of tx ids we assume they form a contigious list of bytes
    let reveal_body: Vec<u8> = reveal_tx_ids.iter().copied().flatten().collect();
    // sign the body for authentication of the sequencer
    let (signature, signer_public_key) = sign_blob_with_private_key(&reveal_body, da_private_key);

    let kind = TransactionKindLightClient::Chunked;
    let kind_bytes = kind.to_bytes();

    // start creating inscription content
    let mut reveal_script_builder = script::Builder::new()
        .push_x_only_key(&public_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(PushBytesBuf::try_from(kind_bytes).expect("Cannot push header"))
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(PushBytesBuf::try_from(signature).expect("Cannot push signature"))
        .push_slice(
            PushBytesBuf::try_from(signer_public_key).expect("Cannot push sequencer public key"),
        );
    // push txids
    for id in reveal_tx_ids {
        reveal_script_builder = reveal_script_builder.push_slice(id);
    }
    // push end if
    reveal_script_builder = reveal_script_builder.push_opcode(OP_ENDIF);

    // This envelope is not finished yet. The random number will be added later

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

        let (control_block, merkle_root) = build_taproot(&reveal_script, public_key, &secp256k1);

        // create commit tx address
        let commit_tx_address = Address::p2tr(&secp256k1, public_key, merkle_root, network);

        let reveal_input_value = get_size_reveal(
            change_address.script_pubkey(),
            reveal_value,
            &reveal_script,
            &control_block,
        ) as u64
            * reveal_fee_rate
            + reveal_value;

        // build commit tx
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

        build_witness(
            &unsigned_commit_tx,
            &mut reveal_tx,
            reveal_script,
            control_block,
            &key_pair,
            &secp256k1,
        );

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

            return Ok(LightClientTxs::Chunked {
                commit_chunks,
                reveal_chunks,
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
