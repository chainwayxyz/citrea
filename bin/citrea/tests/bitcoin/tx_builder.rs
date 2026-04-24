use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use anyhow::{anyhow, bail, Context};
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::opcodes::all::{OP_ENDIF, OP_IF};
use bitcoin::blockdata::script::Builder;
use bitcoin::blockdata::witness::Witness;
use bitcoin::hashes::Hash;
use bitcoin::key::constants::SCHNORR_SIGNATURE_SIZE;
use bitcoin::key::{TapTweak, TweakedPublicKey, UntweakedKeypair};
use bitcoin::opcodes::all::{OP_CHECKSIGVERIFY, OP_NIP};
use bitcoin::opcodes::OP_FALSE;
use bitcoin::script::{PushBytesBuf, ScriptBuf};
use bitcoin::secp256k1::{self, All, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootBuilder};
use bitcoin::{
    Address, Amount, Network, OutPoint, Sequence, TapLeafHash, TapNodeHash, Transaction, TxIn,
    TxOut, Txid,
};
use bitcoin_da::helpers::builders::TxWithId;
use bitcoin_da::spec::utxo::UTXO;
use bitcoin_da::REVEAL_OUTPUT_AMOUNT;
use bitcoincore_rpc::json::SignRawTransactionInput;
use bitcoincore_rpc::RpcApi;
use borsh::to_vec;
use citrea_primitives::compression::compress_blob;
use citrea_primitives::{MAX_TX_BODY_SIZE, REVEAL_TX_PREFIX};
use secp256k1::SECP256K1;
use sha2::{Digest, Sha256};
use sov_rollup_interface::da::{DaTxRequest, DataOnDa};
use sov_rollup_interface::zk::Proof;

use super::utils::PROVER_DA_PRIVATE_KEY;

const REVEAL_OUTPUT_THRESHOLD: u64 = 2_000;

#[derive(Debug, Clone)]
pub(crate) struct UtxoContext {
    pub available_utxos: Vec<UTXO>,
    pub prev_utxo: Option<UTXO>,
}

#[derive(Clone, Debug)]
pub(crate) enum DaTxs {
    Complete {
        commit: Transaction,
        reveal: TxWithId,
    },
    Chunked {
        commit_chunks: Vec<Transaction>,
        reveal_chunks: Vec<Transaction>,
        commit: Transaction,
        reveal: TxWithId,
    },
}

enum RawTxData {
    Complete,
    Chunks(Vec<Vec<u8>>),
}

#[derive(Clone, Copy)]
enum TransactionKind {
    Complete,
    Aggregate,
    Chunks,
    SequencerCommitment,
}

impl TransactionKind {
    fn to_bytes(self) -> [u8; 2] {
        match self {
            Self::Complete => 0u16.to_le_bytes(),
            Self::Aggregate => 1u16.to_le_bytes(),
            Self::Chunks => 2u16.to_le_bytes(),
            Self::SequencerCommitment => 4u16.to_le_bytes(),
        }
    }
}

pub(crate) async fn test_send_separate_chunk_transaction_with_fee_rate<C: RpcApi + Sync>(
    client: &C,
    tx_request: DaTxRequest,
    fee_sat_per_vbyte: f64,
) -> anyhow::Result<Vec<Txid>> {
    let DaTxRequest::ZKProof(zk_proof) = tx_request else {
        bail!("expected ZK proof request");
    };

    let RawTxData::Chunks(chunks) = split_proof(zk_proof)? else {
        bail!("expected chunked proof");
    };

    let da_private_key = SecretKey::from_str(PROVER_DA_PRIVATE_KEY)?;
    let mut all_txids = Vec::with_capacity((chunks.len() + 1) * 2);
    let mut reveal_tx_ids = Vec::with_capacity(chunks.len());
    let mut reveal_wtx_ids = Vec::with_capacity(chunks.len());

    // Build each chunk as an independent commit/reveal pair so the full set can be
    // re-ordered freely when packed into blocks. Broadcasting between iterations
    // causes `list_unspent` to exclude inputs already locked by pending chunks.
    for chunk_body in chunks {
        let change_address = client.get_new_address(None, None).await?.assume_checked();
        let utxos = client
            .list_unspent(None, None, None, None, None)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();

        let DaTxs::Complete { commit, reveal } = create_unsigned_chunk_inscription(
            chunk_body,
            &da_private_key,
            UtxoContext {
                available_utxos: utxos,
                prev_utxo: None,
            },
            change_address,
            fee_sat_per_vbyte,
            fee_sat_per_vbyte,
            Network::Regtest,
            REVEAL_TX_PREFIX,
        )?
        else {
            bail!("expected chunk inscription transactions");
        };

        reveal_tx_ids.push(reveal.tx.compute_txid().to_byte_array());
        reveal_wtx_ids.push(reveal.tx.compute_wtxid().to_byte_array());

        all_txids.extend(broadcast_complete_transactions(client, commit, reveal).await?);
    }

    let aggregate = DataOnDa::Aggregate(reveal_tx_ids, reveal_wtx_ids);
    let body = to_vec(&aggregate).expect("aggregate serialization must succeed");

    let change_address = client.get_new_address(None, None).await?.assume_checked();
    let utxos = client
        .list_unspent(None, None, None, None, None)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    let DaTxs::Complete { commit, reveal } = create_signed_inscription_type_0_or_4(
        body,
        TransactionKind::Aggregate,
        &da_private_key,
        UtxoContext {
            available_utxos: utxos,
            prev_utxo: None,
        },
        change_address,
        fee_sat_per_vbyte,
        fee_sat_per_vbyte,
        Network::Regtest,
        REVEAL_TX_PREFIX,
    )?
    else {
        bail!("expected complete aggregate inscription");
    };

    all_txids.extend(broadcast_complete_transactions(client, commit, reveal).await?);

    Ok(all_txids)
}

pub(crate) async fn test_send_complete_transaction_with_fee_rate<C: RpcApi + Sync>(
    client: &C,
    tx_request: DaTxRequest,
    da_private_key: &str,
    fee_sat_per_vbyte: f64,
) -> anyhow::Result<Vec<Txid>> {
    let (body, kind) = match tx_request {
        DaTxRequest::ZKProof(proof) => {
            let compressed_proof = compress_blob(&proof)?;
            let data = DataOnDa::Complete(compressed_proof);
            (
                to_vec(&data).expect("complete proof serialization must succeed"),
                TransactionKind::Complete,
            )
        }
        DaTxRequest::SequencerCommitment(commitment) => {
            let data = DataOnDa::SequencerCommitment(commitment);
            (
                to_vec(&data).expect("sequencer commitment serialization must succeed"),
                TransactionKind::SequencerCommitment,
            )
        }
        DaTxRequest::BatchProofMethodId(_) => {
            bail!("batch proof method id direct send is not supported by this helper");
        }
    };

    let da_private_key = SecretKey::from_str(da_private_key)?;
    let change_address = client.get_new_address(None, None).await?.assume_checked();
    let utxos = client
        .list_unspent(None, None, None, None, None)
        .await?
        .into_iter()
        .map(Into::into)
        .collect();

    let DaTxs::Complete { commit, reveal } = create_signed_inscription_type_0_or_4(
        body,
        kind,
        &da_private_key,
        UtxoContext {
            available_utxos: utxos,
            prev_utxo: None,
        },
        change_address,
        fee_sat_per_vbyte,
        fee_sat_per_vbyte,
        Network::Regtest,
        REVEAL_TX_PREFIX,
    )?
    else {
        bail!("expected complete inscription transactions");
    };

    broadcast_complete_transactions(client, commit, reveal).await
}

pub(crate) fn create_inscription_type_0(
    body: Vec<u8>,
    da_private_key: &SecretKey,
    utxo_context: UtxoContext,
    change_address: Address,
    commit_fee_rate: f64,
    reveal_fee_rate: f64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> anyhow::Result<DaTxs> {
    create_signed_inscription_type_0_or_4(
        body,
        TransactionKind::Complete,
        da_private_key,
        utxo_context,
        change_address,
        commit_fee_rate,
        reveal_fee_rate,
        network,
        reveal_tx_prefix,
    )
}

fn create_signed_inscription_type_0_or_4(
    body: Vec<u8>,
    kind: TransactionKind,
    da_private_key: &SecretKey,
    utxo_context: UtxoContext,
    change_address: Address,
    commit_fee_rate: f64,
    reveal_fee_rate: f64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> anyhow::Result<DaTxs> {
    let key_pair = UntweakedKeypair::from_secret_key(SECP256K1, da_private_key);
    let (public_key, _) = XOnlyPublicKey::from_keypair(&key_pair);
    let (signature, signer_public_key) = sign_blob_with_private_key(&body, da_private_key);
    let reveal_script =
        build_signed_reveal_script(public_key, kind, signature, signer_public_key, body);

    create_complete_inscription_with_script(
        reveal_script,
        &key_pair,
        public_key,
        utxo_context,
        change_address,
        commit_fee_rate,
        reveal_fee_rate,
        network,
        reveal_tx_prefix,
    )
}

fn create_unsigned_chunk_inscription(
    body: Vec<u8>,
    da_private_key: &SecretKey,
    utxo_context: UtxoContext,
    change_address: Address,
    commit_fee_rate: f64,
    reveal_fee_rate: f64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> anyhow::Result<DaTxs> {
    let key_pair = UntweakedKeypair::from_secret_key(SECP256K1, da_private_key);
    let (public_key, _) = XOnlyPublicKey::from_keypair(&key_pair);
    let reveal_script = build_chunk_reveal_script(public_key, body);

    create_complete_inscription_with_script(
        reveal_script,
        &key_pair,
        public_key,
        utxo_context,
        change_address,
        commit_fee_rate,
        reveal_fee_rate,
        network,
        reveal_tx_prefix,
    )
}

#[allow(clippy::too_many_arguments)]
fn create_complete_inscription_with_script(
    reveal_script: ScriptBuf,
    key_pair: &UntweakedKeypair,
    public_key: XOnlyPublicKey,
    utxo_context: UtxoContext,
    change_address: Address,
    commit_fee_rate: f64,
    reveal_fee_rate: f64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> anyhow::Result<DaTxs> {
    let UtxoContext {
        available_utxos: utxos,
        prev_utxo,
    } = utxo_context;

    let (control_block, merkle_root, tapscript_hash) =
        build_control_block(&reveal_script, public_key, SECP256K1);
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

    let (unsigned_commit_tx, _) = build_commit_transaction(
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
        key_pair,
        SECP256K1,
    );

    mine_reveal_prefix(
        &unsigned_commit_tx,
        &mut reveal_tx,
        tapscript_hash,
        key_pair,
        SECP256K1,
        reveal_tx_prefix,
    );

    verify_commit_address(key_pair, merkle_root, network, &commit_tx_address);

    Ok(DaTxs::Complete {
        commit: unsigned_commit_tx,
        reveal: TxWithId {
            id: reveal_tx.compute_txid(),
            tx: reveal_tx,
        },
    })
}

pub(crate) fn create_inscription_type_1(
    chunks: Vec<Vec<u8>>,
    da_private_key: &SecretKey,
    utxo_context: UtxoContext,
    change_address: Address,
    commit_fee_rate: f64,
    reveal_fee_rate: f64,
    network: Network,
    reveal_tx_prefix: &[u8],
) -> anyhow::Result<DaTxs> {
    let UtxoContext {
        available_utxos: mut utxos,
        mut prev_utxo,
    } = utxo_context;

    let key_pair = UntweakedKeypair::from_secret_key(SECP256K1, da_private_key);
    let (public_key, _) = XOnlyPublicKey::from_keypair(&key_pair);

    let mut commit_chunks = Vec::new();
    let mut reveal_chunks = Vec::new();

    for body in chunks {
        let reveal_script = build_chunk_reveal_script(public_key, body);
        let (control_block, merkle_root, tapscript_hash) =
            build_control_block(&reveal_script, public_key, SECP256K1);
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

        mine_reveal_prefix(
            &unsigned_commit_tx,
            &mut reveal_tx,
            tapscript_hash,
            &key_pair,
            SECP256K1,
            reveal_tx_prefix,
        );

        verify_commit_address(&key_pair, merkle_root, network, &commit_tx_address);

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
            });
        }

        commit_chunks.push(unsigned_commit_tx);
        reveal_chunks.push(reveal_tx);
    }

    let (reveal_tx_ids, reveal_wtx_ids): (Vec<_>, Vec<_>) = reveal_chunks
        .iter()
        .map(|tx| {
            (
                tx.compute_txid().to_byte_array(),
                tx.compute_wtxid().to_byte_array(),
            )
        })
        .unzip();

    let aggregate = DataOnDa::Aggregate(reveal_tx_ids, reveal_wtx_ids);
    let reveal_body = to_vec(&aggregate).expect("aggregate serialization must succeed");
    let (signature, signer_public_key) = sign_blob_with_private_key(&reveal_body, da_private_key);
    let reveal_script = build_signed_reveal_script(
        public_key,
        TransactionKind::Aggregate,
        signature,
        signer_public_key,
        reveal_body,
    );
    let (control_block, merkle_root, tapscript_hash) =
        build_control_block(&reveal_script, public_key, SECP256K1);
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

    let (unsigned_commit_tx, _) = build_commit_transaction(
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

    mine_reveal_prefix(
        &unsigned_commit_tx,
        &mut reveal_tx,
        tapscript_hash,
        &key_pair,
        SECP256K1,
        reveal_tx_prefix,
    );

    verify_commit_address(&key_pair, merkle_root, network, &commit_tx_address);

    Ok(DaTxs::Chunked {
        commit_chunks,
        reveal_chunks,
        commit: unsigned_commit_tx,
        reveal: TxWithId {
            id: reveal_tx.compute_txid(),
            tx: reveal_tx,
        },
    })
}

fn split_proof(zk_proof: Proof) -> anyhow::Result<RawTxData> {
    let original_compressed = compress_blob(&zk_proof)?;

    if original_compressed.len() < MAX_TX_BODY_SIZE {
        Ok(RawTxData::Complete)
    } else {
        let chunks = original_compressed
            .chunks(MAX_TX_BODY_SIZE)
            .map(|chunk| {
                let data = DataOnDa::Chunk(chunk.to_vec());
                to_vec(&data).expect("chunk serialization must succeed")
            })
            .collect();
        Ok(RawTxData::Chunks(chunks))
    }
}

fn build_signed_reveal_script(
    public_key: XOnlyPublicKey,
    kind: TransactionKind,
    signature: Vec<u8>,
    signer_public_key: Vec<u8>,
    body: Vec<u8>,
) -> ScriptBuf {
    let mut builder = Builder::new()
        .push_x_only_key(&public_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(PushBytesBuf::from(kind.to_bytes()))
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(PushBytesBuf::try_from(signature).expect("signature is pushable"))
        .push_slice(PushBytesBuf::try_from(signer_public_key).expect("pubkey is pushable"));

    for chunk in body.chunks(520) {
        builder =
            builder.push_slice(PushBytesBuf::try_from(chunk.to_vec()).expect("body is pushable"));
    }

    builder
        .push_opcode(OP_ENDIF)
        .push_slice(16i64.to_le_bytes())
        .push_opcode(OP_NIP)
        .into_script()
}

fn build_chunk_reveal_script(public_key: XOnlyPublicKey, body: Vec<u8>) -> ScriptBuf {
    let mut builder = Builder::new()
        .push_x_only_key(&public_key)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_slice(PushBytesBuf::from(TransactionKind::Chunks.to_bytes()))
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF);

    for chunk in body.chunks(520) {
        builder =
            builder.push_slice(PushBytesBuf::try_from(chunk.to_vec()).expect("body is pushable"));
    }

    builder
        .push_opcode(OP_ENDIF)
        .push_slice(16i64.to_le_bytes())
        .push_opcode(OP_NIP)
        .into_script()
}

fn build_commit_transaction(
    prev_utxo: Option<UTXO>,
    mut utxos: Vec<UTXO>,
    recipient: Address,
    change_address: Address,
    output_value: u64,
    fee_rate: f64,
) -> anyhow::Result<(Transaction, Vec<UTXO>)> {
    let non_dust_change = 546;
    let size = get_size_commit(
        &[TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0; 32]),
                vout: 0,
            },
            script_sig: Builder::new().into_script(),
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

    if let Some(required_utxo) = &prev_utxo {
        utxos
            .retain(|utxo| !(utxo.vout == required_utxo.vout && utxo.tx_id == required_utxo.tx_id));
    }

    let mut iteration = 0;
    let mut last_size = size;

    let (leftover_utxos, tx) = loop {
        let fee = (last_size as f64 * fee_rate).ceil() as u64;
        let input_total = output_value + fee + non_dust_change;
        let (chosen_utxos, sum, leftover_utxos) =
            choose_utxos(prev_utxo.clone(), &utxos, input_total)?;
        let has_change = (sum - input_total) >= REVEAL_OUTPUT_AMOUNT;

        let outputs = if has_change {
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
        } else {
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
        };

        let inputs = chosen_utxos
            .iter()
            .map(|u| TxIn {
                previous_output: OutPoint {
                    txid: u.tx_id,
                    vout: u.vout,
                },
                script_sig: Builder::new().into_script(),
                witness: Witness::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            })
            .collect::<Vec<_>>();

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
        if iteration > 100 {
            bail!("failed to stabilize commit transaction size");
        }
    };

    Ok((tx, leftover_utxos))
}

fn build_reveal_transaction(
    input_utxo: TxOut,
    input_txid: Txid,
    input_vout: u32,
    recipient: Address,
    output_value: u64,
    fee_rate: f64,
    reveal_script: &ScriptBuf,
    control_block: &ControlBlock,
) -> anyhow::Result<Transaction> {
    let outputs = vec![TxOut {
        value: Amount::from_sat(output_value),
        script_pubkey: recipient.script_pubkey(),
    }];

    let inputs = vec![TxIn {
        previous_output: OutPoint {
            txid: input_txid,
            vout: input_vout,
        },
        script_sig: Builder::new().into_script(),
        witness: Witness::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
    }];

    let size = get_size_reveal(
        recipient.script_pubkey(),
        output_value,
        reveal_script,
        control_block,
    );
    let fee = (size as f64 * fee_rate).ceil() as u64;
    let input_total = output_value + fee;

    if input_utxo.value < Amount::from_sat(REVEAL_OUTPUT_AMOUNT)
        || input_utxo.value < Amount::from_sat(input_total)
    {
        bail!("input UTXO not big enough");
    }

    Ok(Transaction {
        lock_time: LockTime::ZERO,
        version: bitcoin::transaction::Version(2),
        input: inputs,
        output: outputs,
    })
}

fn build_control_block(
    reveal_script: &ScriptBuf,
    public_key: XOnlyPublicKey,
    secp256k1: &Secp256k1<All>,
) -> (ControlBlock, Option<TapNodeHash>, TapLeafHash) {
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .expect("cannot add reveal script")
        .finalize(secp256k1, public_key)
        .expect("cannot finalize taproot tree");

    let tapleaf_hash = TapLeafHash::from_script(reveal_script, LeafVersion::TapScript);
    let control_block = taproot_spend_info
        .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
        .expect("cannot create control block");

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
    let mut sighash_cache = SighashCache::new(reveal_tx);
    let signature_hash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[&commit_tx.output[0]]),
            tapscript_hash,
            bitcoin::sighash::TapSighashType::Default,
        )
        .expect("cannot compute sighash");

    let signature = secp256k1.sign_schnorr(
        &Message::from_digest_slice(signature_hash.as_byte_array())
            .expect("taproot sighash is a valid digest"),
        key_pair,
    );

    let witness = sighash_cache.witness_mut(0).expect("missing witness");
    witness.clear();
    witness.push(signature.as_ref());
    witness.push(reveal_script);
    witness.push(control_block.serialize());
}

fn update_witness(
    commit_tx: &Transaction,
    reveal_tx: &mut Transaction,
    tapscript_hash: TapLeafHash,
    key_pair: &Keypair,
    secp256k1: &Secp256k1<All>,
) {
    let mut sighash_cache = SighashCache::new(reveal_tx);
    let signature_hash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[&commit_tx.output[0]]),
            tapscript_hash,
            bitcoin::sighash::TapSighashType::Default,
        )
        .expect("cannot compute sighash");

    let signature = secp256k1.sign_schnorr(
        &Message::from_digest_slice(signature_hash.as_byte_array())
            .expect("taproot sighash is a valid digest"),
        key_pair,
    );

    let witness = sighash_cache.witness_mut(0).expect("missing witness");
    let reveal_script = witness.nth(1).expect("missing reveal script");
    let control_block = witness.nth(2).expect("missing control block");

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

    for input in &mut tx.input {
        input.witness.push([0; SCHNORR_SIGNATURE_SIZE]);
    }

    tx.vsize()
}

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
        script_sig: Builder::new().into_script(),
        witness,
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
    }];

    let outputs = vec![TxOut {
        value: Amount::from_sat(output_amount),
        script_pubkey: recipient,
    }];

    Transaction {
        input: inputs,
        output: outputs,
        lock_time: LockTime::ZERO,
        version: bitcoin::transaction::Version(2),
    }
    .vsize()
}

fn choose_utxos(
    required_utxo: Option<UTXO>,
    utxos: &[UTXO],
    amount: u64,
) -> anyhow::Result<(Vec<UTXO>, u64, Vec<UTXO>)> {
    let mut chosen_utxos = Vec::new();
    let mut sum = 0;

    if let Some(required) = required_utxo {
        sum += required.amount;
        chosen_utxos.push(required);
    }

    if sum >= amount {
        return Ok((chosen_utxos, sum, utxos.to_vec()));
    }

    let remaining_amount = amount - sum;
    let mut bigger_utxos = utxos
        .iter()
        .filter(|utxo| utxo.amount >= remaining_amount)
        .collect::<Vec<_>>();

    if let Some(utxo) = {
        bigger_utxos.sort_by_key(|utxo| utxo.amount);
        bigger_utxos.first().copied()
    } {
        sum += utxo.amount;
        chosen_utxos.push(utxo.clone());
    } else {
        let mut smaller_utxos = utxos
            .iter()
            .filter(|utxo| utxo.amount < remaining_amount)
            .collect::<Vec<_>>();
        smaller_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

        for utxo in smaller_utxos {
            sum += utxo.amount;
            chosen_utxos.push(utxo.clone());
            if sum >= amount {
                break;
            }
        }

        if sum < amount {
            bail!("not enough UTXOs");
        }
    }

    let input_set = utxos.iter().collect::<HashSet<_>>();
    let chosen_set = chosen_utxos.iter().collect::<HashSet<_>>();
    let leftovers = input_set
        .difference(&chosen_set)
        .copied()
        .cloned()
        .collect::<Vec<_>>();

    Ok((chosen_utxos, sum, leftovers))
}

fn sign_blob_with_private_key(blob: &[u8], private_key: &SecretKey) -> (Vec<u8>, Vec<u8>) {
    let message = calculate_sha256(blob);
    let public_key = secp256k1::PublicKey::from_secret_key(SECP256K1, private_key);
    let message = secp256k1::Message::from_digest(message);
    let signature = SECP256K1.sign_ecdsa(&message, private_key);
    (
        signature.serialize_compact().to_vec(),
        public_key.serialize().to_vec(),
    )
}

fn calculate_sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::default();
    hasher.update(input);
    hasher.finalize().into()
}

fn mine_reveal_prefix(
    commit_tx: &Transaction,
    reveal_tx: &mut Transaction,
    tapscript_hash: TapLeafHash,
    key_pair: &Keypair,
    secp256k1: &Secp256k1<All>,
    prefix: &[u8],
) {
    let mut iterations = 0u32;
    loop {
        if reveal_tx
            .compute_wtxid()
            .as_raw_hash()
            .to_byte_array()
            .starts_with(prefix)
        {
            return;
        }

        iterations += 1;
        if iterations > 16_384 {
            panic!("too many iterations mining reveal prefix");
        }

        update_witness(commit_tx, reveal_tx, tapscript_hash, key_pair, secp256k1);
    }
}

fn verify_commit_address(
    key_pair: &UntweakedKeypair,
    merkle_root: Option<TapNodeHash>,
    network: Network,
    expected_address: &Address,
) {
    let recovery_key_pair = key_pair.tap_tweak(SECP256K1, merkle_root);
    let (x_only_pub_key, _) = recovery_key_pair.to_inner().x_only_public_key();
    assert_eq!(
        Address::p2tr_tweaked(
            TweakedPublicKey::dangerous_assume_tweaked(x_only_pub_key),
            network,
        ),
        *expected_address
    );
}

async fn broadcast_complete_transactions<C: RpcApi + Sync>(
    client: &C,
    commit: Transaction,
    reveal: TxWithId,
) -> anyhow::Result<Vec<Txid>> {
    let all_tx_map = [&commit, &reveal.tx]
        .into_iter()
        .map(|tx| (tx.compute_txid(), tx.clone()))
        .collect::<HashMap<_, _>>();

    let signed_commit = sign_commit_transaction(client, &commit, &all_tx_map).await?;
    let commit_txid = client.send_raw_transaction(&signed_commit).await?;
    let reveal_txid = client
        .send_raw_transaction(&bitcoin::consensus::encode::serialize(&reveal.tx))
        .await?;

    Ok(vec![commit_txid, reveal_txid])
}

async fn sign_commit_transaction<C: RpcApi + Sync>(
    client: &C,
    commit: &Transaction,
    all_tx_map: &HashMap<Txid, Transaction>,
) -> anyhow::Result<Vec<u8>> {
    let mut inputs = Vec::new();
    for input in &commit.input {
        if let Some(entry) = all_tx_map.get(&input.previous_output.txid) {
            inputs.push(SignRawTransactionInput {
                txid: input.previous_output.txid,
                vout: input.previous_output.vout,
                script_pub_key: entry.output[input.previous_output.vout as usize]
                    .script_pubkey
                    .clone(),
                redeem_script: None,
                amount: Some(entry.output[input.previous_output.vout as usize].value),
            });
        }
    }

    let signed = client
        .sign_raw_transaction_with_wallet(commit, Some(&inputs), None)
        .await
        .with_context(|| format!("failed to sign commit {}", commit.compute_txid()))?;

    if let Some(errors) = signed.errors {
        return Err(anyhow!("failed to sign commit transaction: {errors:?}"));
    }

    Ok(signed.hex)
}
