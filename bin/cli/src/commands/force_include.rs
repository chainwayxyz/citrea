use anyhow::{anyhow, Context};
use bitcoin_da::helpers::builders::body_builders::{create_inscription_type_5, DaTxs};
use bitcoin_da::spec::utxo::UTXO;
use bitcoin_da::utxo_manager::UtxoContext;
use sov_rollup_interface::da::{DataOnDa, ForcedTransaction};
use tracing::info;

/// Execute the force-include command: creates and broadcasts a Bitcoin inscription
/// containing a forced EVM transaction.
pub(crate) async fn force_include(
    rlp_tx_hex: String,
    da_private_key: String,
    fee_rate: f64,
    network: String,
    reveal_tx_prefix: Vec<u8>,
    bitcoin_url: String,
    bitcoin_user: String,
    bitcoin_password: String,
) -> anyhow::Result<()> {
    // 1. Decode the hex RLP transaction
    let rlp_tx = hex::decode(rlp_tx_hex.trim_start_matches("0x"))
        .context("Failed to decode hex RLP transaction")?;

    if rlp_tx.is_empty() {
        return Err(anyhow!("RLP transaction is empty"));
    }

    info!("Preparing forced transaction inscription ({} bytes)", rlp_tx.len());

    // 2. Build ForcedTransaction and serialize as DataOnDa
    let forced_tx = ForcedTransaction {
        rlp_tx,
        l1_block_height: 0, // Will be set by the sequencer upon extraction
    };
    let data_on_da = DataOnDa::ForcedTransaction(forced_tx);
    let body = borsh::to_vec(&data_on_da).context("Failed to serialize DataOnDa")?;

    // 3. Parse the DA private key
    let da_key_bytes =
        hex::decode(da_private_key.trim_start_matches("0x")).context("Failed to decode DA private key")?;
    let da_secret_key = bitcoin::secp256k1::SecretKey::from_slice(&da_key_bytes)
        .context("Invalid DA private key")?;

    // 4. Determine bitcoin network
    let btc_network = match network.as_str() {
        "mainnet" => bitcoin::Network::Bitcoin,
        "testnet" | "testnet3" => bitcoin::Network::Testnet,
        "signet" => bitcoin::Network::Signet,
        "regtest" => bitcoin::Network::Regtest,
        _ => return Err(anyhow!("Unknown network: {}", network)),
    };

    // 5. Connect to Bitcoin RPC and get UTXOs
    let client = bitcoincore_rpc::Client::new(
        &bitcoin_url,
        bitcoincore_rpc::Auth::UserPass(bitcoin_user, bitcoin_password),
    )
    .context("Failed to connect to Bitcoin RPC")?;

    // Get wallet UTXOs
    let unspent = client
        .list_unspent(Some(1), None, None, None, None)
        .context("Failed to list unspent UTXOs")?;

    if unspent.is_empty() {
        return Err(anyhow!("No UTXOs available in wallet"));
    }

    let utxos: Vec<UTXO> = unspent
        .into_iter()
        .filter(|u| u.spendable)
        .map(|u| UTXO {
            tx_id: u.txid,
            vout: u.vout,
            address: u.address.map(|a| a.as_unchecked().clone()),
            script_pubkey: u.script_pub_key.to_hex_string(),
            amount: u.amount.to_sat(),
            confirmations: u.confirmations,
            spendable: true,
            solvable: u.solvable.unwrap_or(false),
        })
        .collect();

    info!("Found {} spendable UTXOs", utxos.len());

    // Get change address from wallet
    let change_address = client
        .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))
        .context("Failed to get new change address")?
        .require_network(btc_network)
        .context("Change address network mismatch")?;

    // 6. Build the inscription transactions
    let utxo_context = UtxoContext {
        available_utxos: utxos,
        prev_utxo: None,
    };

    let da_txs = create_inscription_type_5(
        body,
        &da_secret_key,
        utxo_context,
        change_address,
        fee_rate,
        fee_rate,
        btc_network,
        &reveal_tx_prefix,
    )
    .context("Failed to create inscription transactions")?;

    let (commit_tx, reveal_tx) = match da_txs {
        DaTxs::ForcedTransaction { commit, reveal } => (commit, reveal),
        _ => return Err(anyhow!("Unexpected DaTxs variant")),
    };

    // 7. Sign and broadcast commit transaction
    let signed_commit = client
        .sign_raw_transaction_with_wallet(&commit_tx, None, None)
        .context("Failed to sign commit transaction")?;

    if !signed_commit.complete {
        return Err(anyhow!("Commit transaction signing incomplete"));
    }

    let signed_commit_tx = signed_commit
        .transaction()
        .ok_or_else(|| anyhow!("No transaction in signing result"))?;

    let commit_txid = client
        .send_raw_transaction(&signed_commit_tx)
        .context("Failed to broadcast commit transaction")?;

    info!("Commit transaction broadcast: {}", commit_txid);

    // 8. Broadcast reveal transaction (already signed via taproot script)
    let reveal_txid = client
        .send_raw_transaction(&reveal_tx.tx)
        .context("Failed to broadcast reveal transaction")?;

    info!("Reveal transaction broadcast: {}", reveal_txid);

    println!("Forced transaction inscription created successfully!");
    println!("  Commit TXID: {}", commit_txid);
    println!("  Reveal TXID: {}", reveal_txid);

    Ok(())
}
