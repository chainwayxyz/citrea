//! This module contains functions to create transactions for the DA layer.

use core::result::Result::Ok;
use std::time::Instant;

use bitcoin::absolute::{LockTime, Time, LOCK_TIME_THRESHOLD};
use bitcoin::blockdata::opcodes::all::{OP_ENDIF, OP_IF};
use bitcoin::blockdata::opcodes::OP_FALSE;
use bitcoin::blockdata::script;
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, TweakedPublicKey, UntweakedKeypair};
use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_NIP};
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{SecretKey, XOnlyPublicKey};
use bitcoin::{Address, Network, Transaction};
use metrics::histogram;
use secp256k1::SECP256K1;
use serde::Serialize;
use sov_rollup_interface::da::DataOnDa;
use tracing::{info, instrument, trace, warn};

use super::{
    build_commit_transaction, build_control_block, build_reveal_transaction, build_witness,
    get_size_reveal, sign_blob_with_private_key, update_witness, TransactionKind, TxWithId,
};
use crate::spec::utxo::UTXO;
use crate::utxo_manager::UtxoContext;
use crate::{REVEAL_OUTPUT_AMOUNT, REVEAL_OUTPUT_THRESHOLD};

/// These are real blobs we put on DA.
pub(crate) enum RawTxData {
    /// borsh(DataOnDa::Complete(compress(Proof)))
    Complete(Vec<u8>),
    /// let compressed = compress(borsh(Proof))
    /// let chunks = compressed.chunks(MAX_TX_BODY_SIZE)
    /// [borsh(DataOnDa::Chunk(chunk)) for chunk in chunks]
    Chunks(Vec<Vec<u8>>),
    /// borsh(DataOnDa::SecurityCouncilTx(SecurityCouncilTx))
    SecurityCouncilTx(Vec<u8>),
    /// borsh(DataOnDa::SequencerCommitment(SequencerCommitment))
    SequencerCommitment(Vec<u8>),
}

/// This is a list of txs we need to send to DA
#[derive(Serialize, Clone, Debug)]
pub enum DaTxs {
    /// Complete proof.
    Complete {
        /// Unsigned
        commit: Transaction,
        /// Signed
        reveal: TxWithId,
    },
    /// Chunked proof.
    Chunked {
        /// Unsigned
        commit_chunks: Vec<Transaction>,
        /// Signed
        reveal_chunks: Vec<Transaction>,
        /// Unsigned
        commit: Transaction,
        /// Signed
        reveal: TxWithId,
    },
    /// Security council transaction.
    SecurityCouncilTx {
        /// Unsigned
        commit: Transaction,
        /// Signed
        reveal: TxWithId,
    },
    /// Sequencer commitment.
    SequencerCommitment {
        /// Unsigned
        commit: Transaction,
        /// Signed
        reveal: TxWithId,
    },
}

/// Creates the light client transactions (commit and reveal).
/// Based on data type, the number of transactions may vary.
/// In the end, reveal txs will be mined with a nonce to have
/// wtxid start from the `reveal_tx_prefix`.
#[allow(clippy::too_many_arguments)]
#[instrument(level = "trace", skip_all, err)]
pub fn create_inscription_transactions(
    data: RawTxData,
    da_private_key: SecretKey,
    utxo_context: UtxoContext,
    change_address: Address,
    commit_fee_rate: f64,
    reveal_fee_rate: f64,
    network: Network,
    reveal_tx_prefix: Vec<u8>,
) -> Result<DaTxs, anyhow::Error> {
    match data {
        RawTxData::Complete(body) => create_inscription_type_0(
            body,
            &da_private_key,
            utxo_context,
            change_address,
            commit_fee_rate,
            reveal_fee_rate,
            network,
            &reveal_tx_prefix,
        ),
        RawTxData::Chunks(body) => create_inscription_type_1(
            body,
            &da_private_key,
            utxo_context,
            change_address,
            commit_fee_rate,
            reveal_fee_rate,
            network,
            &reveal_tx_prefix,
        ),
        RawTxData::SecurityCouncilTx(body) => create_inscription_type_3(
            body,
            &da_private_key,
            utxo_context,
            change_address,
            commit_fee_rate,
            reveal_fee_rate,
            network,
            &reveal_tx_prefix,
        ),
        RawTxData::SequencerCommitment(body) => create_inscription_type_4(
            body,
            &da_private_key,
            utxo_context,
            change_address,
            commit_fee_rate,
            reveal_fee_rate,
            network,
            &reveal_tx_prefix,
        ),
    }
}

/// Creates the inscription transactions Type 0 - Complete
#[allow(clippy::too_many_arguments)]
#[instrument(level = "trace", skip_all, err)]
pub fn create_inscription_type_0(
    body: Vec<u8>,
    da_private_key: &SecretKey,
    utxo_context: UtxoContext,
    change_address: Address,
    commit_fee_rate: f64,
    reveal_fee_rate: f64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> Result<DaTxs, anyhow::Error> {
    let UtxoContext {
        available_utxos: utxos,
        prev_utxo,
    } = utxo_context;

    // Create reveal key
    let key_pair = UntweakedKeypair::from_secret_key(SECP256K1, da_private_key);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let kind = TransactionKind::Complete;
    let kind_bytes = kind.to_bytes();

    // sign the body for authentication of the sequencer
    let (signature, signer_public_key) = sign_blob_with_private_key(&body, da_private_key);

    let start = Instant::now();

    // start creating inscription content
    let mut reveal_script_builder = script::Builder::new()
        .push_x_only_key(&public_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(PushBytesBuf::from(kind_bytes))
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

    // Nonce is kept for legacy reasons but is now fixed at 16.
    // Prefix mining is now done by iterating over lock_time instead.
    let nonce: i64 = 16; // >= 16 to avoid OP_PUSHNUM_X interpretation

    // push nonce
    reveal_script_builder = reveal_script_builder
        .push_slice(nonce.to_le_bytes())
        // drop the second item, bc there is a big chance it's 0 (tx kind) and nonce is >= 16
        .push_opcode(OP_NIP);

    // finalize reveal script
    let reveal_script = reveal_script_builder.into_script();

    let (control_block, merkle_root, tapscript_hash) =
        build_control_block(&reveal_script, public_key, SECP256K1);

    // create commit tx address
    let commit_tx_address = Address::p2tr(SECP256K1, public_key, merkle_root, network);

    let reveal_value = REVEAL_OUTPUT_AMOUNT;
    let fee = (get_size_reveal(
        change_address.script_pubkey(),
        reveal_value,
        &reveal_script,
        &control_block,
    ) as f64
        * reveal_fee_rate)
        .ceil() as u64;
    let reveal_input_value = fee + reveal_value + REVEAL_OUTPUT_THRESHOLD;

    // build commit tx
    // we don't need leftover_utxos because they will be requested from bitcoind next call
    let (unsigned_commit_tx, _leftover_utxos) = build_commit_transaction(
        prev_utxo,
        utxos,
        commit_tx_address.clone(),
        change_address.clone(),
        reveal_input_value,
        commit_fee_rate,
    )?;

    let input_to_reveal = unsigned_commit_tx.output[0].clone();
    let commit_txid = unsigned_commit_tx.compute_txid();

    let mut reveal_tx = build_reveal_transaction(
        input_to_reveal,
        commit_txid,
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
        SECP256K1,
    );

    // Mine for the reveal tx prefix by iterating over lock_time values.
    // Starting from LOCK_TIME_THRESHOLD (500_000_000) is safe because it represents
    // a Unix timestamp from 1985, and with a two-byte prefix requiring on average 2^16
    // iterations, the resulting timestamp (~500_065_536) is still in 1985, making the
    // transaction spendable immediately (equivalent to nLockTime == 0).
    let mut lock_time = LOCK_TIME_THRESHOLD;
    loop {
        let iterations = lock_time - LOCK_TIME_THRESHOLD;
        if iterations > 0 && iterations % 1000 == 0 {
            trace!(iterations, "Mining for complete reveal tx prefix");
            if iterations > 16384 {
                warn!("Too many iterations mining for complete reveal tx prefix");
            }
        }

        let reveal_wtxid = reveal_tx.compute_wtxid();
        let reveal_hash = reveal_wtxid.as_raw_hash().to_byte_array();
        // check if first N bytes equal to the given prefix
        if reveal_hash.starts_with(reveal_tx_prefix) {
            // check if inscription locked to the correct address
            let recovery_key_pair = key_pair.tap_tweak(SECP256K1, merkle_root);
            let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
            assert_eq!(
                Address::p2tr_tweaked(
                    TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
                    network,
                ),
                commit_tx_address
            );

            histogram!("complete_mine_da_transaction").record(
                Instant::now()
                    .saturating_duration_since(start)
                    .as_secs_f64(),
            );

            if let Some(root) = merkle_root {
                info!("Taproot merkle root for inscription - Complete: {}", root);
            }
            return Ok(DaTxs::Complete {
                commit: unsigned_commit_tx,
                reveal: TxWithId {
                    id: reveal_tx.compute_txid(),
                    tx: reveal_tx,
                },
            });
        } else {
            reveal_tx.lock_time = LockTime::Seconds(Time::from_consensus(lock_time).unwrap());
            update_witness(
                &unsigned_commit_tx,
                &mut reveal_tx,
                tapscript_hash,
                &key_pair,
                SECP256K1,
            );
            lock_time += 1;
        }
    }
}

/// Creates the inscription transactions Type 1 - Chunked
#[allow(clippy::too_many_arguments)]
#[instrument(level = "trace", skip_all, err)]
pub fn create_inscription_type_1(
    chunks: Vec<Vec<u8>>,
    da_private_key: &SecretKey,
    utxo_context: UtxoContext,
    change_address: Address,
    commit_fee_rate: f64,
    reveal_fee_rate: f64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> Result<DaTxs, anyhow::Error> {
    let UtxoContext {
        available_utxos: mut utxos,
        mut prev_utxo,
    } = utxo_context;

    // Create reveal key
    let key_pair = UntweakedKeypair::from_secret_key(SECP256K1, da_private_key);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let mut commit_chunks: Vec<Transaction> = vec![];
    let mut reveal_chunks: Vec<Transaction> = vec![];

    let start = Instant::now();

    for body in chunks {
        let kind = TransactionKind::Chunks;
        let kind_bytes = kind.to_bytes();

        // start creating inscription content
        let mut reveal_script_builder = script::Builder::new()
            .push_x_only_key(&public_key)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(PushBytesBuf::from(kind_bytes))
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF);
        // push body in chunks of 520 bytes
        for chunk in body.chunks(520) {
            reveal_script_builder = reveal_script_builder.push_slice(
                PushBytesBuf::try_from(chunk.to_vec()).expect("Cannot push body chunk"),
            );
        }
        // push end if
        reveal_script_builder = reveal_script_builder.push_opcode(OP_ENDIF);

        // Nonce is kept for legacy reasons but is now fixed at 16.
        // Prefix mining is now done by iterating over lock_time instead.
        let nonce: i64 = 16; // >= 16 to avoid OP_PUSHNUM_X interpretation

        // push nonce
        reveal_script_builder = reveal_script_builder
            .push_slice(nonce.to_le_bytes())
            // drop the second item, bc there is a big chance it's 0 (tx kind) and nonce is >= 16
            .push_opcode(OP_NIP);

        // finalize reveal script
        let reveal_script = reveal_script_builder.into_script();

        let (control_block, merkle_root, tapscript_hash) =
            build_control_block(&reveal_script, public_key, SECP256K1);

        // create commit tx address
        let commit_tx_address = Address::p2tr(SECP256K1, public_key, merkle_root, network);

        let reveal_value = REVEAL_OUTPUT_AMOUNT;
        let fee = (get_size_reveal(
            change_address.script_pubkey(),
            reveal_value,
            &reveal_script,
            &control_block,
        ) as f64
            * reveal_fee_rate)
            .ceil() as u64;
        let reveal_input_value = fee + reveal_value + REVEAL_OUTPUT_THRESHOLD;

        // build commit tx
        let (unsigned_commit_tx, leftover_utxos) = build_commit_transaction(
            prev_utxo.clone(),
            utxos.clone(),
            commit_tx_address.clone(),
            change_address.clone(),
            reveal_input_value,
            commit_fee_rate,
        )?;

        let input_to_reveal = unsigned_commit_tx.output[0].clone();
        let commit_txid = unsigned_commit_tx.compute_txid();

        let mut reveal_tx = build_reveal_transaction(
            input_to_reveal,
            commit_txid,
            0,
            change_address.clone(),
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
            SECP256K1,
        );

        // Mine for the reveal tx prefix by iterating over lock_time values.
        // Starting from LOCK_TIME_THRESHOLD (500_000_000) is safe because it represents
        // a Unix timestamp from 1985, and with a two-byte prefix requiring on average 2^16
        // iterations, the resulting timestamp (~500_065_536) is still in 1985, making the
        // transaction spendable immediately (equivalent to nLockTime == 0).
        let mut lock_time = LOCK_TIME_THRESHOLD;
        loop {
            let iterations = lock_time - LOCK_TIME_THRESHOLD;
            if iterations > 0 && iterations % 1000 == 0 {
                trace!(iterations, "Mining for chunk reveal tx prefix");
                if iterations > 16384 {
                    warn!("Too many iterations mining for chunk reveal tx prefix");
                }
            }

            let reveal_wtxid = reveal_tx.compute_wtxid();
            let reveal_hash = reveal_wtxid.as_raw_hash().to_byte_array();

            // check if first N bytes equal to the given prefix
            if reveal_hash.starts_with(reveal_tx_prefix) {
                // check if inscription locked to the correct address
                let recovery_key_pair = key_pair.tap_tweak(SECP256K1, merkle_root);
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

                // Replace utxos with leftovers so we don't use prev utxos in next chunks
                utxos = leftover_utxos;

                if unsigned_commit_tx.output.len() > 1 {
                    utxos.push(UTXO {
                        tx_id: unsigned_commit_tx.compute_txid(),
                        vout: 1,
                        address: None,
                        script_pubkey: unsigned_commit_tx.output[1].script_pubkey.to_hex_string(),
                        amount: unsigned_commit_tx.output[1].value.to_sat(),
                        confirmations: 0,
                        spendable: true,
                        solvable: true,
                    })
                }

                commit_chunks.push(unsigned_commit_tx);
                reveal_chunks.push(reveal_tx);

                if let Some(root) = merkle_root {
                    info!("Taproot merkle root for inscription - Chunked: {}", root);
                }

                break;
            } else {
                reveal_tx.lock_time = LockTime::Seconds(Time::from_consensus(lock_time).unwrap());
                update_witness(
                    &unsigned_commit_tx,
                    &mut reveal_tx,
                    tapscript_hash,
                    &key_pair,
                    SECP256K1,
                );
                lock_time += 1;
            }
        }
    }

    let (reveal_tx_ids, reveal_wtx_ids): (Vec<_>, Vec<_>) = reveal_chunks
        .iter()
        .map(|tx| {
            (
                tx.compute_txid().to_byte_array(),
                tx.compute_wtxid().to_byte_array(),
            )
        })
        .collect();

    let aggregate = DataOnDa::Aggregate(reveal_tx_ids, reveal_wtx_ids);

    // To sign the list of tx ids we assume they form a contiguous list of bytes
    let reveal_body: Vec<u8> =
        borsh::to_vec(&aggregate).expect("Aggregate serialize must not fail");
    // sign the body for authentication of the sequencer
    let (signature, signer_public_key) = sign_blob_with_private_key(&reveal_body, da_private_key);

    let kind = TransactionKind::Aggregate;
    let kind_bytes = kind.to_bytes();

    // start creating inscription content
    let mut reveal_script_builder = script::Builder::new()
        .push_x_only_key(&public_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(PushBytesBuf::from(kind_bytes))
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(PushBytesBuf::try_from(signature).expect("Cannot push signature"))
        .push_slice(
            PushBytesBuf::try_from(signer_public_key).expect("Cannot push sequencer public key"),
        );
    // push body in chunks of 520 bytes
    for chunk in reveal_body.chunks(520) {
        reveal_script_builder = reveal_script_builder
            .push_slice(PushBytesBuf::try_from(chunk.to_vec()).expect("Cannot push body chunk"));
    }
    // push end if
    reveal_script_builder = reveal_script_builder.push_opcode(OP_ENDIF);

    // Nonce is kept for legacy reasons but is now fixed at 16.
    // Prefix mining is now done by iterating over lock_time instead.
    let nonce: i64 = 16; // >= 16 to avoid OP_PUSHNUM_X interpretation

    // push nonce
    reveal_script_builder = reveal_script_builder
        .push_slice(nonce.to_le_bytes())
        // drop the second item, bc there is a big chance it's 0 (tx kind) and nonce is >= 16
        .push_opcode(OP_NIP);

    // finalize reveal script
    let reveal_script = reveal_script_builder.into_script();

    let (control_block, merkle_root, tapscript_hash) =
        build_control_block(&reveal_script, public_key, SECP256K1);

    // create commit tx address
    let commit_tx_address = Address::p2tr(SECP256K1, public_key, merkle_root, network);

    let reveal_value = REVEAL_OUTPUT_AMOUNT;
    let fee = (get_size_reveal(
        change_address.script_pubkey(),
        reveal_value,
        &reveal_script,
        &control_block,
    ) as f64
        * reveal_fee_rate)
        .ceil() as u64;
    let reveal_input_value = fee + reveal_value + REVEAL_OUTPUT_THRESHOLD;

    // build commit tx
    let (unsigned_commit_tx, _leftover_utxos) = build_commit_transaction(
        prev_utxo,
        utxos,
        commit_tx_address.clone(),
        change_address.clone(),
        reveal_input_value,
        commit_fee_rate,
    )?;

    let input_to_reveal = unsigned_commit_tx.output[0].clone();
    let commit_txid = unsigned_commit_tx.compute_txid();

    let mut reveal_tx = build_reveal_transaction(
        input_to_reveal,
        commit_txid,
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
        SECP256K1,
    );

    // Mine for the reveal tx prefix by iterating over lock_time values.
    // Starting from LOCK_TIME_THRESHOLD (500_000_000) is safe because it represents
    // a Unix timestamp from 1985, and with a two-byte prefix requiring on average 2^16
    // iterations, the resulting timestamp (~500_065_536) is still in 1985, making the
    // transaction spendable immediately (equivalent to nLockTime == 0).
    let mut lock_time = LOCK_TIME_THRESHOLD;
    loop {
        let iterations = lock_time - LOCK_TIME_THRESHOLD;
        if iterations > 0 && iterations % 1000 == 0 {
            trace!(iterations, "Mining for aggregate reveal tx prefix");
            if iterations > 16384 {
                warn!("Too many iterations mining for aggregate reveal tx prefix");
            }
        }

        let reveal_wtxid = reveal_tx.compute_wtxid();
        let reveal_hash = reveal_wtxid.as_raw_hash().to_byte_array();

        // check if first N bytes equal to the given prefix
        if reveal_hash.starts_with(reveal_tx_prefix) {
            // check if inscription locked to the correct address
            let recovery_key_pair = key_pair.tap_tweak(SECP256K1, merkle_root);
            let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
            assert_eq!(
                Address::p2tr_tweaked(
                    TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
                    network,
                ),
                commit_tx_address
            );

            histogram!("chunked_mine_da_transaction").record(
                Instant::now()
                    .saturating_duration_since(start)
                    .as_secs_f64(),
            );

            if let Some(root) = merkle_root {
                info!("Taproot merkle root for inscription - Aggregate: {}", root);
            }
            return Ok(DaTxs::Chunked {
                commit_chunks,
                reveal_chunks,
                commit: unsigned_commit_tx,
                reveal: TxWithId {
                    id: reveal_tx.compute_txid(),
                    tx: reveal_tx,
                },
            });
        } else {
            reveal_tx.lock_time = LockTime::Seconds(Time::from_consensus(lock_time).unwrap());
            update_witness(
                &unsigned_commit_tx,
                &mut reveal_tx,
                tapscript_hash,
                &key_pair,
                SECP256K1,
            );
            lock_time += 1;
        }
    }
}

/// Creates the inscription transactions Type 3 - SecurityCouncilTx
#[allow(clippy::too_many_arguments)]
#[instrument(level = "trace", skip_all, err)]
pub fn create_inscription_type_3(
    body: Vec<u8>,
    da_private_key: &SecretKey,
    utxo_context: UtxoContext,
    change_address: Address,
    commit_fee_rate: f64,
    reveal_fee_rate: f64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> Result<DaTxs, anyhow::Error> {
    let UtxoContext {
        available_utxos: utxos,
        prev_utxo,
    } = utxo_context;

    // Create reveal key
    let key_pair = UntweakedKeypair::from_secret_key(SECP256K1, da_private_key);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let kind = TransactionKind::SecurityCouncilTx;
    let kind_bytes = kind.to_bytes();

    let start = Instant::now();

    // start creating inscription content
    let mut reveal_script_builder = script::Builder::new()
        .push_x_only_key(&public_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(PushBytesBuf::from(kind_bytes))
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF);

    // push body in chunks of 520 bytes
    // Body includes security council signatures and public keys
    for chunk in body.chunks(520) {
        reveal_script_builder = reveal_script_builder
            .push_slice(PushBytesBuf::try_from(chunk.to_vec()).expect("Cannot push body chunk"));
    }
    // push end if
    reveal_script_builder = reveal_script_builder.push_opcode(OP_ENDIF);

    // Nonce is kept for legacy reasons but is now fixed at 16.
    // Prefix mining is now done by iterating over lock_time instead.
    let nonce: i64 = 16; // >= 16 to avoid OP_PUSHNUM_X interpretation

    // push nonce
    reveal_script_builder = reveal_script_builder
        .push_slice(nonce.to_le_bytes())
        // drop the second item, bc there is a big chance it's 0 (tx kind) and nonce is >= 16
        .push_opcode(OP_NIP);

    // finalize reveal script
    let reveal_script = reveal_script_builder.into_script();

    let (control_block, merkle_root, tapscript_hash) =
        build_control_block(&reveal_script, public_key, SECP256K1);

    // create commit tx address
    let commit_tx_address = Address::p2tr(SECP256K1, public_key, merkle_root, network);

    let reveal_value = REVEAL_OUTPUT_AMOUNT;
    let fee = (get_size_reveal(
        change_address.script_pubkey(),
        reveal_value,
        &reveal_script,
        &control_block,
    ) as f64
        * reveal_fee_rate)
        .ceil() as u64;
    let reveal_input_value = fee + reveal_value + REVEAL_OUTPUT_THRESHOLD;

    // build commit tx
    // we don't need leftover_utxos because they will be requested from bitcoind next call
    let (unsigned_commit_tx, _leftover_utxos) = build_commit_transaction(
        prev_utxo,
        utxos,
        commit_tx_address.clone(),
        change_address.clone(),
        reveal_input_value,
        commit_fee_rate,
    )?;

    let input_to_reveal = unsigned_commit_tx.output[0].clone();
    let commit_txid = unsigned_commit_tx.compute_txid();

    let mut reveal_tx = build_reveal_transaction(
        input_to_reveal,
        commit_txid,
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
        SECP256K1,
    );

    // Mine for the reveal tx prefix by iterating over lock_time values.
    // Starting from LOCK_TIME_THRESHOLD (500_000_000) is safe because it represents
    // a Unix timestamp from 1985, and with a two-byte prefix requiring on average 2^16
    // iterations, the resulting timestamp (~500_065_536) is still in 1985, making the
    // transaction spendable immediately (equivalent to nLockTime == 0).
    let mut lock_time = LOCK_TIME_THRESHOLD;
    loop {
        let iterations = lock_time - LOCK_TIME_THRESHOLD;
        if iterations > 0 && iterations % 1000 == 0 {
            trace!(
                iterations,
                "Mining for batch proof method id reveal tx prefix"
            );
            if iterations > 16384 {
                warn!("Too many iterations mining for batch proof method id reveal tx prefix");
            }
        }

        let reveal_wtxid = reveal_tx.compute_wtxid();
        let reveal_hash = reveal_wtxid.as_raw_hash().to_byte_array();
        // check if first N bytes equal to the given prefix
        if reveal_hash.starts_with(reveal_tx_prefix) {
            // check if inscription locked to the correct address
            let recovery_key_pair = key_pair.tap_tweak(SECP256K1, merkle_root);
            let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
            assert_eq!(
                Address::p2tr_tweaked(
                    TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
                    network,
                ),
                commit_tx_address
            );

            histogram!("batch_proof_method_id_mine_da_transaction").record(
                Instant::now()
                    .saturating_duration_since(start)
                    .as_secs_f64(),
            );

            if let Some(root) = merkle_root {
                info!(
                    "Taproot merkle root for inscription - SecurityCouncilTx: {}",
                    root
                );
            }
            return Ok(DaTxs::SecurityCouncilTx {
                commit: unsigned_commit_tx,
                reveal: TxWithId {
                    id: reveal_tx.compute_txid(),
                    tx: reveal_tx,
                },
            });
        } else {
            reveal_tx.lock_time = LockTime::Seconds(Time::from_consensus(lock_time).unwrap());
            update_witness(
                &unsigned_commit_tx,
                &mut reveal_tx,
                tapscript_hash,
                &key_pair,
                SECP256K1,
            );
            lock_time += 1;
        }
    }
}

/// Creates the batch proof transactions Type 4 - SequencerCommitment
#[allow(clippy::too_many_arguments)]
#[instrument(level = "trace", skip_all, err)]
pub fn create_inscription_type_4(
    body: Vec<u8>,
    da_private_key: &SecretKey,
    utxo_context: UtxoContext,
    change_address: Address,
    commit_fee_rate: f64,
    reveal_fee_rate: f64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> Result<DaTxs, anyhow::Error> {
    debug_assert!(
        body.len() < 520,
        "The body of a serialized sequencer commitment exceeds 520 bytes"
    );

    let UtxoContext {
        available_utxos: utxos,
        prev_utxo,
    } = utxo_context;

    // Create reveal key
    let key_pair = UntweakedKeypair::from_secret_key(SECP256K1, da_private_key);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let kind = TransactionKind::SequencerCommitment;
    let kind_bytes = kind.to_bytes();

    // sign the body for authentication of the sequencer
    let (signature, signer_public_key) = sign_blob_with_private_key(&body, da_private_key);

    let start = Instant::now();

    // start creating inscription content
    let mut reveal_script_builder = script::Builder::new()
        .push_x_only_key(&public_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(PushBytesBuf::from(kind_bytes))
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(PushBytesBuf::try_from(signature).expect("Cannot push signature"))
        .push_slice(
            PushBytesBuf::try_from(signer_public_key).expect("Cannot push sequencer public key"),
        )
        .push_slice(PushBytesBuf::try_from(body).expect("Cannot push sequencer commitment"))
        .push_opcode(OP_ENDIF);

    // Nonce is kept for legacy reasons but is now fixed at 16.
    // Prefix mining is now done by iterating over lock_time instead.
    let nonce: i64 = 16; // >= 16 to avoid OP_PUSHNUM_X interpretation

    // push nonce
    reveal_script_builder = reveal_script_builder
        .push_slice(nonce.to_le_bytes())
        // drop the second item, bc there is a big chance it's 0 (tx kind) and nonce is >= 16
        .push_opcode(OP_NIP);

    // finalize reveal script
    let reveal_script = reveal_script_builder.into_script();

    let (control_block, merkle_root, tapscript_hash) =
        build_control_block(&reveal_script, public_key, SECP256K1);

    // create commit tx address
    let commit_tx_address = Address::p2tr(SECP256K1, public_key, merkle_root, network);

    let reveal_value = REVEAL_OUTPUT_AMOUNT;
    let fee = (get_size_reveal(
        change_address.script_pubkey(),
        reveal_value,
        &reveal_script,
        &control_block,
    ) as f64
        * reveal_fee_rate)
        .ceil() as u64;
    let reveal_input_value = fee + reveal_value + REVEAL_OUTPUT_THRESHOLD;

    // build commit tx
    // we don't need leftover_utxos because they will be requested from bitcoind next call
    let (unsigned_commit_tx, _leftover_utxos) = build_commit_transaction(
        prev_utxo,
        utxos,
        commit_tx_address.clone(),
        change_address.clone(),
        reveal_input_value,
        commit_fee_rate,
    )?;

    let input_to_reveal = unsigned_commit_tx.output[0].clone();
    let commit_txid = unsigned_commit_tx.compute_txid();

    let mut reveal_tx = build_reveal_transaction(
        input_to_reveal,
        commit_txid,
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
        SECP256K1,
    );

    // Mine for the reveal tx prefix by iterating over lock_time values.
    // Starting from LOCK_TIME_THRESHOLD (500_000_000) is safe because it represents
    // a Unix timestamp from 1985, and with a two-byte prefix requiring on average 2^16
    // iterations, the resulting timestamp (~500_065_536) is still in 1985, making the
    // transaction spendable immediately (equivalent to nLockTime == 0).
    let mut lock_time = LOCK_TIME_THRESHOLD;
    loop {
        let iterations = lock_time - LOCK_TIME_THRESHOLD;
        if iterations > 0 && iterations % 1000 == 0 {
            trace!(
                iterations,
                "Mining for sequencer commitment reveal tx prefix"
            );
            if iterations > 16384 {
                warn!("Too many iterations mining for sequencer commitment reveal tx prefix");
            }
        }

        let reveal_wtxid = reveal_tx.compute_wtxid();
        let reveal_hash = reveal_wtxid.as_raw_hash().to_byte_array();
        // check if first N bytes equal to the given prefix
        if reveal_hash.starts_with(reveal_tx_prefix) {
            // check if inscription locked to the correct address
            let recovery_key_pair = key_pair.tap_tweak(SECP256K1, merkle_root);
            let (x_only_pub_key, _parity) = recovery_key_pair.to_inner().x_only_public_key();
            assert_eq!(
                Address::p2tr_tweaked(
                    TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
                    network,
                ),
                commit_tx_address
            );

            histogram!("sequencer_commitment_mine_da_transaction").record(
                Instant::now()
                    .saturating_duration_since(start)
                    .as_secs_f64(),
            );

            if let Some(root) = merkle_root {
                info!("Taproot merkle root for inscription - Commitment: {}", root);
            }
            return Ok(DaTxs::SequencerCommitment {
                commit: unsigned_commit_tx,
                reveal: TxWithId {
                    id: reveal_tx.compute_txid(),
                    tx: reveal_tx,
                },
            });
        } else {
            reveal_tx.lock_time = LockTime::Seconds(Time::from_consensus(lock_time).unwrap());
            update_witness(
                &unsigned_commit_tx,
                &mut reveal_tx,
                tapscript_hash,
                &key_pair,
                SECP256K1,
            );
            lock_time += 1;
        }
    }
}
