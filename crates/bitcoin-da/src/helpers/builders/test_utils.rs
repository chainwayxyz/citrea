use core::result::Result::Ok;

use bitcoin::blockdata::opcodes::all::{OP_ENDIF, OP_IF};
use bitcoin::blockdata::opcodes::OP_FALSE;
use bitcoin::blockdata::script;
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, TweakedPublicKey, UntweakedKeypair};
use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_NIP};
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{SecretKey, XOnlyPublicKey};
use bitcoin::{Address, Amount, Network};
use secp256k1::SECP256K1;
use tracing::{trace, warn};

use super::{
    build_commit_transaction, build_reveal_transaction, build_taproot, build_witness,
    get_size_reveal, sign_blob_with_private_key, update_witness, TransactionKind,
};
use crate::helpers::builders::body_builders::DaTxs;
use crate::helpers::builders::TxWithId;
use crate::spec::utxo::UTXO;
use crate::{REVEAL_OUTPUT_AMOUNT, REVEAL_OUTPUT_THRESHOLD};

// Returns (chunk commit tx, chunk reveal tx)
#[allow(clippy::too_many_arguments)]
pub fn test_create_single_chunk(
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
    let key_pair = UntweakedKeypair::from_secret_key(SECP256K1, da_private_key);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

    let kind = TransactionKind::Chunks;
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
        reveal_script_builder = reveal_script_builder
            .push_slice(PushBytesBuf::try_from(chunk.to_vec()).expect("Cannot push body chunk"));
    }
    // push end if
    let reveal_script_builder = reveal_script_builder.push_opcode(OP_ENDIF);

    // Start loop to find a 'nonce' i.e. random number that makes the reveal tx hash starting with zeros given length
    let mut nonce: i64 = 16; // skip the first digits to avoid OP_PUSHNUM_X
    loop {
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
            build_taproot(&reveal_script, public_key, SECP256K1);

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
    }
}

#[allow(clippy::too_many_arguments)]
pub fn test_create_single_aggregate(
    reveal_body: Vec<u8>,
    da_private_key: &SecretKey,
    utxos: Vec<UTXO>,
    change_address: Address,
    network: Network,
    reveal_fee_rate: u64,
    commit_fee_rate: u64,
    prev_utxo: Option<UTXO>,
    reveal_tx_prefix: &[u8],
) -> Result<DaTxs, anyhow::Error> {
    // sign the body for authentication of the sequencer
    let key_pair = UntweakedKeypair::from_secret_key(SECP256K1, da_private_key);
    let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);
    let (signature, signer_public_key) = sign_blob_with_private_key(&reveal_body, da_private_key);

    let kind = TransactionKind::Aggregate;
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
            build_taproot(&reveal_script, public_key, SECP256K1);

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
    }
}
