//! This module contains functions to create transactions for the DA layer.

use core::result::Result::Ok;
use std::time::Instant;

use bitcoin::blockdata::opcodes::all::{OP_ENDIF, OP_IF};
use bitcoin::blockdata::opcodes::OP_FALSE;
use bitcoin::blockdata::script;
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, TweakedPublicKey, UntweakedKeypair};
use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_NIP};
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{SecretKey, XOnlyPublicKey};
use bitcoin::{Address, Amount, Network, Transaction};
use metrics::histogram;
use secp256k1::SECP256K1;
use serde::Serialize;
use sov_rollup_interface::da::DataOnDa;
use tracing::{instrument, trace, warn};

use super::{
    build_commit_transaction, build_control_block, build_reveal_transaction, build_witness,
    get_size_reveal, sign_blob_with_private_key, update_witness, TransactionKind, TxWithId,
};
use crate::spec::utxo::UTXO;
use crate::{REVEAL_OUTPUT_AMOUNT, REVEAL_OUTPUT_THRESHOLD};

/// These are real blobs we put on DA.
pub(crate) enum RawTxData {
    /// borsh(DataOnDa::Complete(compress(Proof)))
    Complete(Vec<u8>),
    /// let compressed = compress(borsh(Proof))
    /// let chunks = compressed.chunks(MAX_TX_BODY_SIZE)
    /// [borsh(DataOnDa::Chunk(chunk)) for chunk in chunks]
    Chunks(Vec<Vec<u8>>),
    /// borsh(DataOnDa::BatchProofMethodId(MethodId))
    BatchProofMethodId(Vec<u8>),
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
    /// BatchProof method id.
    BatchProofMethodId {
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
    prev_utxo: Option<UTXO>,
    utxos: Vec<UTXO>,
    change_address: Address,
    commit_fee_rate: u64,
    reveal_fee_rate: u64,
    network: Network,
    reveal_tx_prefix: Vec<u8>,
) -> Result<DaTxs, anyhow::Error> {
    match data {
        RawTxData::Complete(body) => create_inscription_type_0(
            body,
            &da_private_key,
            prev_utxo,
            utxos,
            change_address,
            commit_fee_rate,
            reveal_fee_rate,
            network,
            &reveal_tx_prefix,
        ),
        RawTxData::Chunks(body) => create_inscription_type_1(
            body,
            &da_private_key,
            prev_utxo,
            utxos,
            change_address,
            commit_fee_rate,
            reveal_fee_rate,
            network,
            &reveal_tx_prefix,
        ),
        RawTxData::BatchProofMethodId(body) => create_inscription_type_3(
            body,
            &da_private_key,
            prev_utxo,
            utxos,
            change_address,
            commit_fee_rate,
            reveal_fee_rate,
            network,
            &reveal_tx_prefix,
        ),
        RawTxData::SequencerCommitment(body) => create_inscription_type_4(
            body,
            &da_private_key,
            prev_utxo,
            utxos,
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
    prev_utxo: Option<UTXO>,
    utxos: Vec<UTXO>,
    change_address: Address,
    commit_fee_rate: u64,
    reveal_fee_rate: u64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> Result<DaTxs, anyhow::Error> {
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

    // This envelope is not finished yet. The random number will be added later

    // Start loop to find a 'nonce' i.e. random number that makes the reveal tx hash starting with zeros given length
    let mut nonce: i64 = 16; // skip the first digits to avoid OP_PUSHNUM_X
    loop {
        if nonce % 1000 == 0 {
            trace!(nonce, "Trying to find commit & reveal nonce");
            if nonce > 16384 {
                warn!("Too many iterations finding nonce");
            }
        }

        let mut reveal_script_builder = reveal_script_builder.clone();

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
            utxos.clone(),
            commit_tx_address.clone(),
            change_address.clone(),
            reveal_input_value,
            commit_fee_rate,
        )?;

        let input_to_reveal = unsigned_commit_tx.output[0].clone();

        let mut reveal_tx = build_reveal_transaction(
            input_to_reveal.clone(),
            unsigned_commit_tx.compute_txid(),
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

        let min_commit_value = Amount::from_sat(fee + reveal_value);
        while unsigned_commit_tx.output[0].value >= min_commit_value
            && reveal_tx.output[0].value > Amount::from_sat(REVEAL_OUTPUT_AMOUNT)
        {
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

                histogram!("mine_da_transaction").record(
                    Instant::now()
                        .saturating_duration_since(start)
                        .as_secs_f64(),
                );

                return Ok(DaTxs::Complete {
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
                    SECP256K1,
                );
            }
        }

        nonce += 1;
    }
}

/// Creates the inscription transactions Type 1 - Chunked
#[allow(clippy::too_many_arguments)]
#[instrument(level = "trace", skip_all, err)]
pub fn create_inscription_type_1(
    chunks: Vec<Vec<u8>>,
    da_private_key: &SecretKey,
    mut prev_utxo: Option<UTXO>,
    mut utxos: Vec<UTXO>,
    change_address: Address,
    commit_fee_rate: u64,
    reveal_fee_rate: u64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> Result<DaTxs, anyhow::Error> {
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
        let reveal_script_builder = reveal_script_builder.push_opcode(OP_ENDIF);

        // Start loop to find a 'nonce' i.e. random number that makes the reveal tx hash starting with zeros given length
        let mut nonce: i64 = 16; // skip the first digits to avoid OP_PUSHNUM_X
        'mine_chunk: loop {
            if nonce % 1000 == 0 {
                trace!(nonce, "Trying to find commit & reveal nonce for chunk");
                if nonce > 16384 {
                    warn!("Too many iterations finding nonce for chunk");
                }
            }
            // ownerships are moved to the loop
            let mut reveal_script_builder = reveal_script_builder.clone();

            // push nonce
            reveal_script_builder = reveal_script_builder
                .push_slice(nonce.to_le_bytes())
                // drop the second item, bc there is a big chance it's 0 (tx kind) and nonce is >= 16
                .push_opcode(OP_NIP);
            nonce += 1;

            // finalize reveal script
            let reveal_script = reveal_script_builder.into_script();

            let (control_block, merkle_root, tapscript_hash) =
                build_control_block(&reveal_script, public_key, SECP256K1);

            // create commit tx address
            let commit_tx_address = Address::p2tr(SECP256K1, public_key, merkle_root, network);

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
            let (mut unsigned_commit_tx, leftover_utxos) = build_commit_transaction(
                prev_utxo.clone(),
                utxos.clone(),
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

            let min_commit_value = Amount::from_sat(fee + reveal_value);
            while unsigned_commit_tx.output[0].value >= min_commit_value
                && reveal_tx.output[0].value > Amount::from_sat(REVEAL_OUTPUT_AMOUNT)
            {
                let reveal_wtxid = reveal_tx.compute_wtxid();
                let reveal_hash = reveal_wtxid.as_raw_hash().to_byte_array();

                // check if first N bytes equal to the given prefix
                if reveal_hash.starts_with(reveal_tx_prefix) {
                    // check if inscription locked to the correct address
                    let recovery_key_pair = key_pair.tap_tweak(SECP256K1, merkle_root);
                    let (x_only_pub_key, _parity) =
                        recovery_key_pair.to_inner().x_only_public_key();
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
                            script_pubkey: unsigned_commit_tx.output[0]
                                .script_pubkey
                                .to_hex_string(),
                            amount: unsigned_commit_tx.output[1].value.to_sat(),
                            confirmations: 0,
                            spendable: true,
                            solvable: true,
                        })
                    }

                    commit_chunks.push(unsigned_commit_tx);
                    reveal_chunks.push(reveal_tx);

                    break 'mine_chunk;
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
                        SECP256K1,
                    );
                }
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

    // This envelope is not finished yet. The random number will be added later

    // Start loop to find a 'nonce' i.e. random number that makes the reveal tx hash starting with zeros given length
    let mut nonce: i64 = 16; // skip the first digits to avoid OP_PUSHNUM_X
    loop {
        if nonce % 1000 == 0 {
            trace!(nonce, "Trying to find commit & reveal nonce for aggr");
            if nonce > 16384 {
                warn!("Too many iterations finding nonce for aggr");
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
        nonce += 1;

        // finalize reveal script
        let reveal_script = reveal_script_builder.into_script();

        let (control_block, merkle_root, tapscript_hash) =
            build_control_block(&reveal_script, public_key, SECP256K1);

        // create commit tx address
        let commit_tx_address = Address::p2tr(SECP256K1, public_key, merkle_root, network);

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
        let (mut unsigned_commit_tx, _leftover_utxos) = build_commit_transaction(
            prev_utxo.clone(),
            utxos,
            commit_tx_address.clone(),
            change_address.clone(),
            reveal_input_value,
            commit_fee_rate,
        )?;

        let input_to_reveal = unsigned_commit_tx.output[0].clone();

        let mut reveal_tx = build_reveal_transaction(
            input_to_reveal.clone(),
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
            SECP256K1,
        );

        let min_commit_value = Amount::from_sat(fee + reveal_value);
        while unsigned_commit_tx.output[0].value >= min_commit_value
            && reveal_tx.output[0].value > Amount::from_sat(REVEAL_OUTPUT_AMOUNT)
        {
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

                histogram!("mine_da_transaction").record(
                    Instant::now()
                        .saturating_duration_since(start)
                        .as_secs_f64(),
                );

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
                unsigned_commit_tx.output[0].value -= Amount::ONE_SAT;
                unsigned_commit_tx.output[1].value += Amount::ONE_SAT;
                reveal_tx.output[0].value -= Amount::ONE_SAT;
                reveal_tx.input[0].previous_output.txid = unsigned_commit_tx.compute_txid();
                update_witness(
                    &unsigned_commit_tx,
                    &mut reveal_tx,
                    tapscript_hash,
                    &key_pair,
                    SECP256K1,
                );
            }
        }
    }
}

/// Creates the inscription transactions Type 3 - BatchProofMethodId
#[allow(clippy::too_many_arguments)]
#[instrument(level = "trace", skip_all, err)]
pub fn create_inscription_type_3(
    body: Vec<u8>,
    da_private_key: &SecretKey,
    prev_utxo: Option<UTXO>,
    utxos: Vec<UTXO>,
    change_address: Address,
    commit_fee_rate: u64,
    reveal_fee_rate: u64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> Result<DaTxs, anyhow::Error> {
    // Create reveal key
    let key_pair = UntweakedKeypair::from_secret_key(SECP256K1, da_private_key);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let kind = TransactionKind::BatchProofMethodId;
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

    // This envelope is not finished yet. The random number will be added later

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
            build_control_block(&reveal_script, public_key, SECP256K1);

        // create commit tx address
        let commit_tx_address = Address::p2tr(SECP256K1, public_key, merkle_root, network);

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
            SECP256K1,
        );

        let min_commit_value = Amount::from_sat(fee + reveal_value);
        while unsigned_commit_tx.output[0].value >= min_commit_value
            && reveal_tx.output[0].value > Amount::from_sat(REVEAL_OUTPUT_AMOUNT)
        {
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

                histogram!("mine_da_transaction").record(
                    Instant::now()
                        .saturating_duration_since(start)
                        .as_secs_f64(),
                );

                return Ok(DaTxs::BatchProofMethodId {
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
                    SECP256K1,
                );
            }
        }

        nonce += 1;
    }
}

/// Creates the batch proof transactions Type 4 - SequencerCommitment
#[allow(clippy::too_many_arguments)]
#[instrument(level = "trace", skip_all, err)]
pub fn create_inscription_type_4(
    body: Vec<u8>,
    da_private_key: &SecretKey,
    prev_utxo: Option<UTXO>,
    utxos: Vec<UTXO>,
    change_address: Address,
    commit_fee_rate: u64,
    reveal_fee_rate: u64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> Result<DaTxs, anyhow::Error> {
    debug_assert!(
        body.len() < 520,
        "The body of a serialized sequencer commitment exceeds 520 bytes"
    );
    // Create reveal key
    let key_pair = UntweakedKeypair::from_secret_key(SECP256K1, da_private_key);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let kind = TransactionKind::SequencerCommitment;
    let kind_bytes = kind.to_bytes();

    // sign the body for authentication of the sequencer
    let (signature, signer_public_key) = sign_blob_with_private_key(&body, da_private_key);

    let start = Instant::now();

    // start creating inscription content
    let reveal_script_builder = script::Builder::new()
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
            build_control_block(&reveal_script, public_key, SECP256K1);

        // create commit tx address
        let commit_tx_address = Address::p2tr(SECP256K1, public_key, merkle_root, network);

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
            SECP256K1,
        );

        let min_commit_value = Amount::from_sat(fee + reveal_value);
        while unsigned_commit_tx.output[0].value >= min_commit_value
            && reveal_tx.output[0].value > Amount::from_sat(REVEAL_OUTPUT_AMOUNT)
        {
            // tracing::info!("reveal output: {}", reveal_tx.output[0].value);
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

                histogram!("mine_da_transaction").record(
                    Instant::now()
                        .saturating_duration_since(start)
                        .as_secs_f64(),
                );

                return Ok(DaTxs::SequencerCommitment {
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
                    SECP256K1,
                );
            }
        }

        nonce += 1;
    }
}
