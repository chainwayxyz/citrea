use core::str::FromStr;

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::constants::SCHNORR_SIGNATURE_SIZE;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::SecretKey;
use bitcoin::taproot::ControlBlock;
use bitcoin::{Address, Amount, ScriptBuf, TxOut, Txid};

use super::light_client_proof_namespace::LightClientTxs;
use crate::helpers::builders::sign_blob_with_private_key;
use crate::helpers::compression::{compress_blob, decompress_blob};
use crate::helpers::parsers::{parse_light_client_transaction, ParsedLightClientTransaction};
use crate::spec::utxo::UTXO;
use crate::REVEAL_OUTPUT_AMOUNT;

#[test]
fn compression_decompression() {
    let blob = std::fs::read("test_data/blob.txt").unwrap();

    // compress and measure time
    let time = std::time::Instant::now();
    let compressed_blob = compress_blob(&blob);
    println!("compression time: {:?}", time.elapsed());

    // decompress and measure time
    let time = std::time::Instant::now();
    let decompressed_blob = decompress_blob(&compressed_blob);
    println!("decompression time: {:?}", time.elapsed());

    assert_eq!(blob, decompressed_blob);

    // size
    println!("blob size: {}", blob.len());
    println!("compressed blob size: {}", compressed_blob.len());
    println!(
        "compression ratio: {}",
        (blob.len() as f64) / (compressed_blob.len() as f64)
    );
}

#[allow(clippy::type_complexity)]
fn get_mock_data() -> (Vec<u8>, Address, Vec<UTXO>) {
    let body = vec![100; 1000];
    let address =
        Address::from_str("bc1pp8qru0ve43rw9xffmdd8pvveths3cx6a5t6mcr0xfn9cpxx2k24qf70xq9")
            .unwrap()
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap();
    let utxos = vec![
        UTXO {
            tx_id: Txid::from_str(
                "4cfbec13cf1510545f285cceceb6229bd7b6a918a8f6eba1dbee64d26226a3b7",
            )
            .unwrap(),
            vout: 0,
            address: Some(
                Address::from_str("bc1pp8qru0ve43rw9xffmdd8pvveths3cx6a5t6mcr0xfn9cpxx2k24qf70xq9")
                    .unwrap(),
            ),
            script_pubkey: address.script_pubkey().to_hex_string(),
            amount: 1_000_000,
            confirmations: 100,
            spendable: true,
            solvable: true,
        },
        UTXO {
            tx_id: Txid::from_str(
                "44990141674ff56ed6fee38879e497b2a726cddefd5e4d9b7bf1c4e561de4347",
            )
            .unwrap(),
            vout: 0,
            address: Some(
                Address::from_str("bc1pp8qru0ve43rw9xffmdd8pvveths3cx6a5t6mcr0xfn9cpxx2k24qf70xq9")
                    .unwrap(),
            ),
            script_pubkey: address.script_pubkey().to_hex_string(),
            amount: 100_000,
            confirmations: 100,
            spendable: true,
            solvable: true,
        },
        UTXO {
            tx_id: Txid::from_str(
                "4dbe3c10ee0d6bf16f9417c68b81e963b5bccef3924bbcb0885c9ea841912325",
            )
            .unwrap(),
            vout: 0,
            address: Some(
                Address::from_str("bc1pp8qru0ve43rw9xffmdd8pvveths3cx6a5t6mcr0xfn9cpxx2k24qf70xq9")
                    .unwrap(),
            ),
            script_pubkey: address.script_pubkey().to_hex_string(),
            amount: 10_000,
            confirmations: 100,
            spendable: true,
            solvable: true,
        },
    ];

    (body, address, utxos)
}

#[test]
fn choose_utxos() {
    let (_, _, utxos) = get_mock_data();

    let (chosen_utxos, sum, leftover_utxos) = super::choose_utxos(None, &utxos, 105_000).unwrap();

    assert_eq!(sum, 1_000_000);
    assert_eq!(chosen_utxos.len(), 1);
    assert_eq!(chosen_utxos[0], utxos[0]);
    assert_eq!(leftover_utxos.len(), 2);

    let (chosen_utxos, sum, leftover_utxos) = super::choose_utxos(None, &utxos, 1_005_000).unwrap();

    assert_eq!(sum, 1_100_000);
    assert_eq!(chosen_utxos.len(), 2);
    assert_eq!(chosen_utxos[0], utxos[0]);
    assert_eq!(chosen_utxos[1], utxos[1]);
    assert_eq!(leftover_utxos.len(), 1);

    let (chosen_utxos, sum, leftover_utxos) = super::choose_utxos(None, &utxos, 100_000).unwrap();

    assert_eq!(sum, 100_000);
    assert_eq!(chosen_utxos.len(), 1);
    assert_eq!(chosen_utxos[0], utxos[1]);
    assert_eq!(leftover_utxos.len(), 2);

    let (chosen_utxos, sum, leftover_utxos) = super::choose_utxos(None, &utxos, 90_000).unwrap();

    assert_eq!(sum, 100_000);
    assert_eq!(chosen_utxos.len(), 1);
    assert_eq!(chosen_utxos[0], utxos[1]);
    assert_eq!(leftover_utxos.len(), 2);

    let res = super::choose_utxos(None, &utxos, 100_000_000);

    assert!(res.is_err());
    assert_eq!(format!("{}", res.unwrap_err()), "not enough UTXOs");
}

#[test]
fn build_commit_transaction() {
    let (_, address, utxos) = get_mock_data();

    let recipient =
        Address::from_str("bc1p2e37kuhnsdc5zvc8zlj2hn6awv3ruavak6ayc8jvpyvus59j3mwqwdt0zc")
            .unwrap()
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap();
    let (mut tx, leftover_utxos) = super::build_commit_transaction(
        None,
        utxos.clone(),
        recipient.clone(),
        address.clone(),
        5_000,
        8,
    )
    .unwrap();
    assert_eq!(leftover_utxos.len(), 2);

    tx.input[0].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
            .unwrap()
            .as_ref(),
    );

    // 154 vB * 8 sat/vB = 1232 sats
    // 5_000 + 1232 = 6232
    // input: 10000
    // outputs: 5_000 + 3.768
    assert_eq!(tx.vsize(), 154);
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 2);
    assert_eq!(tx.output[0].value, Amount::from_sat(5_000));
    assert_eq!(tx.output[0].script_pubkey, recipient.script_pubkey());
    assert_eq!(tx.output[1].value, Amount::from_sat(3_768));
    assert_eq!(tx.output[1].script_pubkey, address.script_pubkey());

    let (mut tx, leftover_utxos) = super::build_commit_transaction(
        None,
        utxos.clone(),
        recipient.clone(),
        address.clone(),
        5_000,
        45,
    )
    .unwrap();
    assert_eq!(leftover_utxos.len(), 2);

    tx.input[0].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
            .unwrap()
            .as_ref(),
    );

    // 111 vB * 45 sat/vB = 4.995 sats
    // 5_000 + 4928 = 9995
    // input: 10000
    // outputs: 5_000
    assert_eq!(tx.vsize(), 111);
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.output[0].value, Amount::from_sat(5_000));
    assert_eq!(tx.output[0].script_pubkey, recipient.script_pubkey());

    let (mut tx, leftover_utxos) = super::build_commit_transaction(
        None,
        utxos.clone(),
        recipient.clone(),
        address.clone(),
        5_000,
        32,
    )
    .unwrap();
    assert_eq!(leftover_utxos.len(), 2);

    tx.input[0].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
            .unwrap()
            .as_ref(),
    );

    // you expect
    // 154 vB * 32 sat/vB = 4.928 sats
    // 5_000 + 4928 = 9928
    // input: 10000
    // outputs: 5_000 72
    // instead do
    // input: 10000
    // outputs: 5_000
    // so size is actually 111
    assert_eq!(tx.vsize(), 111);
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.output[0].value, Amount::from_sat(5_000));
    assert_eq!(tx.output[0].script_pubkey, recipient.script_pubkey());

    let (mut tx, leftover_utxos) = super::build_commit_transaction(
        None,
        utxos.clone(),
        recipient.clone(),
        address.clone(),
        1_050_000,
        5,
    )
    .unwrap();
    assert_eq!(leftover_utxos.len(), 1);

    tx.input[0].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
            .unwrap()
            .as_ref(),
    );
    tx.input[1].witness.push(
        Signature::from_slice(&[0; SCHNORR_SIGNATURE_SIZE])
            .unwrap()
            .as_ref(),
    );

    // 212 vB * 5 sat/vB = 1060 sats
    // 1_050_000 + 1060 = 1_051_060
    // inputs: 1_000_000 100_000
    // outputs: 1_050_000 8940
    assert_eq!(tx.vsize(), 212);
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);
    assert_eq!(tx.output[0].value, Amount::from_sat(1_050_000));
    assert_eq!(tx.output[0].script_pubkey, recipient.script_pubkey());
    assert_eq!(tx.output[1].value, Amount::from_sat(48940));
    assert_eq!(tx.output[1].script_pubkey, address.script_pubkey());

    let prev_tx = tx;
    let prev_tx_id = prev_tx.compute_txid();
    let tx = super::build_commit_transaction(
        Some(UTXO {
            tx_id: prev_tx_id,
            vout: 0,
            script_pubkey: prev_tx.output[0].script_pubkey.to_hex_string(),
            address: None,
            amount: prev_tx.output[0].value.to_sat(),
            confirmations: 0,
            spendable: true,
            solvable: true,
        }),
        utxos.clone(),
        recipient.clone(),
        address.clone(),
        100_000_000_000,
        32,
    );

    assert!(tx.is_err());
    assert_eq!(format!("{}", tx.unwrap_err()), "not enough UTXOs");

    let prev_utxos: Vec<UTXO> = prev_tx
        .output
        .iter()
        .enumerate()
        .map(|(i, o)| UTXO {
            tx_id: prev_tx_id,
            vout: i as u32,
            script_pubkey: o.script_pubkey.to_hex_string(),
            address: None,
            confirmations: 0,
            amount: o.value.to_sat(),
            spendable: true,
            solvable: true,
        })
        .collect();
    let prev_utxo: Vec<_> = utxos.clone().into_iter().chain(prev_utxos).collect();
    assert_eq!(prev_utxo.len(), 5);

    let (tx, leftover_utxos) = super::build_commit_transaction(
        Some(UTXO {
            tx_id: prev_tx_id,
            vout: 0,
            script_pubkey: prev_tx.output[0].script_pubkey.to_hex_string(),
            address: None,
            amount: prev_tx.output[0].value.to_sat(),
            confirmations: 0,
            spendable: true,
            solvable: true,
        }),
        prev_utxo,
        recipient.clone(),
        address.clone(),
        50000,
        32,
    )
    .unwrap();
    assert_eq!(leftover_utxos.len(), 4);

    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.input[0].previous_output.txid, prev_tx_id);

    let tx = super::build_commit_transaction(
        None,
        utxos.clone(),
        recipient.clone(),
        address.clone(),
        100_000_000_000,
        32,
    );

    assert!(tx.is_err());
    assert_eq!(format!("{}", tx.unwrap_err()), "not enough UTXOs");

    let tx = super::build_commit_transaction(
        None,
        vec![UTXO {
            tx_id: Txid::from_str(
                "4cfbec13cf1510545f285cceceb6229bd7b6a918a8f6eba1dbee64d26226a3b7",
            )
            .unwrap(),
            vout: 0,
            address: Some(
                Address::from_str("bc1pp8qru0ve43rw9xffmdd8pvveths3cx6a5t6mcr0xfn9cpxx2k24qf70xq9")
                    .unwrap(),
            ),
            script_pubkey: address.script_pubkey().to_hex_string(),
            amount: 152,
            confirmations: 100,
            spendable: true,
            solvable: true,
        }],
        recipient.clone(),
        address.clone(),
        100_000_000_000,
        32,
    );

    assert!(tx.is_err());
    assert_eq!(format!("{}", tx.unwrap_err()), "not enough UTXOs");
}

#[test]
fn build_reveal_transaction() {
    let (_, address, utxos) = get_mock_data();

    let utxo = utxos.first().unwrap();
    let script = ScriptBuf::from_hex("62a58f2674fd840b6144bea2e63ebd35c16d7fd40252a2f28b2a01a648df356343e47976d7906a0e688bf5e134b6fd21bd365c016b57b1ace85cf30bf1206e27").unwrap();
    let control_block = ControlBlock::decode(&[
        193, 165, 246, 250, 6, 222, 28, 9, 130, 28, 217, 67, 171, 11, 229, 62, 48, 206, 219, 111,
        155, 208, 6, 7, 119, 63, 146, 90, 227, 254, 231, 232, 249,
    ])
    .unwrap(); // should be 33 bytes

    let mut tx = super::build_reveal_transaction(
        TxOut {
            value: Amount::from_sat(utxo.amount),
            script_pubkey: ScriptBuf::from_hex(utxo.script_pubkey.as_str()).unwrap(),
        },
        utxo.tx_id,
        utxo.vout,
        address.clone(),
        REVEAL_OUTPUT_AMOUNT,
        8,
        &script,
        &control_block,
    )
    .unwrap();

    tx.input[0].witness.push([0; SCHNORR_SIGNATURE_SIZE]);
    tx.input[0].witness.push(script.clone());
    tx.input[0].witness.push(control_block.serialize());

    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.input[0].previous_output.txid, utxo.tx_id);
    assert_eq!(tx.input[0].previous_output.vout, utxo.vout);

    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.output[0].value, Amount::from_sat(REVEAL_OUTPUT_AMOUNT));
    assert_eq!(tx.output[0].script_pubkey, address.script_pubkey());

    let utxo = utxos.get(2).unwrap();

    let tx = super::build_reveal_transaction(
        TxOut {
            value: Amount::from_sat(utxo.amount),
            script_pubkey: ScriptBuf::from_hex(utxo.script_pubkey.as_str()).unwrap(),
        },
        utxo.tx_id,
        utxo.vout,
        address.clone(),
        REVEAL_OUTPUT_AMOUNT,
        75,
        &script,
        &control_block,
    );

    assert!(tx.is_err());
    assert_eq!(format!("{}", tx.unwrap_err()), "input UTXO not big enough");

    let utxo = utxos.get(2).unwrap();

    let tx = super::build_reveal_transaction(
        TxOut {
            value: Amount::from_sat(utxo.amount),
            script_pubkey: ScriptBuf::from_hex(utxo.script_pubkey.as_str()).unwrap(),
        },
        utxo.tx_id,
        utxo.vout,
        address.clone(),
        9999,
        1,
        &script,
        &control_block,
    );

    assert!(tx.is_err());
    assert_eq!(format!("{}", tx.unwrap_err()), "input UTXO not big enough");
}
#[tokio::test]
async fn create_inscription_transactions() {
    let (body, address, utxos) = get_mock_data();

    let da_private_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");

    // sign the body for authentication of the sequencer
    let (signature, signer_public_key) = sign_blob_with_private_key(&body, &da_private_key);

    let tx_prefix = &[0u8];
    let LightClientTxs::Complete { commit, reveal } =
        super::light_client_proof_namespace::create_zkproof_transactions(
            body.clone(),
            da_private_key,
            None,
            utxos.clone(),
            address.clone(),
            546,
            12,
            10,
            bitcoin::Network::Bitcoin,
            tx_prefix.to_vec(),
        )
        .await
        .unwrap()
    else {
        panic!("Unexpected tx kind was produced");
    };

    // check pow
    assert!(reveal
        .tx
        .compute_wtxid()
        .as_byte_array()
        .starts_with(tx_prefix));

    // check outputs
    assert_eq!(commit.output.len(), 2, "commit tx should have 2 outputs");

    let reveal = reveal.tx;
    assert_eq!(reveal.output.len(), 1, "reveal tx should have 1 output");

    assert_eq!(
        commit.input[0].previous_output.txid, utxos[2].tx_id,
        "utxo to inscribe should be chosen correctly"
    );
    assert_eq!(
        commit.input[0].previous_output.vout, utxos[2].vout,
        "utxo to inscribe should be chosen correctly"
    );

    assert_eq!(
        reveal.input[0].previous_output.txid,
        commit.compute_txid(),
        "reveal should use commit as input"
    );
    assert_eq!(
        reveal.input[0].previous_output.vout, 0,
        "reveal should use commit as input"
    );

    assert_eq!(
        reveal.output[0].script_pubkey,
        address.script_pubkey(),
        "reveal should pay to the correct address"
    );

    // check inscription
    let inscription = parse_light_client_transaction(&reveal).unwrap();
    let ParsedLightClientTransaction::Complete(inscription) = inscription else {
        panic!("Unexpected tx kind");
    };

    assert_eq!(inscription.body, body, "body should be correct");
    assert_eq!(
        inscription.signature, signature,
        "signature should be correct"
    );
    assert_eq!(
        inscription.public_key, signer_public_key,
        "sequencer public key should be correct"
    );
}
