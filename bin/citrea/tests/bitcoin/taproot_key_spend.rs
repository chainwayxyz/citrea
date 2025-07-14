use std::str::FromStr;

use async_trait::async_trait;
use bitcoin::blockdata::locktime::absolute::LockTime;
use bitcoin::key::{TapTweak, UntweakedKeypair};
use bitcoin::secp256k1::{SecretKey, SECP256K1};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_da::helpers::builders::body_builders::{create_inscription_type_0, DaTxs};
use bitcoin_da::spec::utxo::UTXO;
use bitcoincore_rpc::RpcApi;
use citrea_e2e::config::{BitcoinConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::NodeT;
use citrea_e2e::Result;

use crate::bitcoin::utils::PROVER_DA_PRIVATE_KEY;

/// Test key spend path to recover funds from a commit transaction
/// This shows that recovering funds if the reveal transaction fails is possible
async fn test_key_spend_recovery(
    client: &bitcoincore_rpc::Client,
    commit_tx: &Transaction,
    commit_vout: usize,
    destination_address: &Address,
    private_key: &SecretKey,
    merkle_root: Option<bitcoin::taproot::TapNodeHash>,
) -> Result<bitcoin::Txid> {
    let key_pair = UntweakedKeypair::from_secret_key(SECP256K1, private_key);

    let commit_output = &commit_tx.output[commit_vout];
    let commit_amount = commit_output.value;

    let fee = Amount::from_sat(1000);
    let spend_amount = commit_amount - fee;

    let mut key_spend_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: commit_tx.compute_txid(),
                vout: commit_vout as u32,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: spend_amount,
            script_pubkey: destination_address.script_pubkey(),
        }],
    };

    let sighash_type = TapSighashType::Default;
    let prevouts = vec![commit_output];
    let prevouts = Prevouts::All(&prevouts);

    let tweaked_key_pair = key_pair.tap_tweak(SECP256K1, merkle_root);

    let sighash = SighashCache::new(&key_spend_tx).taproot_key_spend_signature_hash(
        0,
        &prevouts,
        sighash_type,
    )?;

    let signature = SECP256K1.sign_schnorr(&sighash.into(), &tweaked_key_pair.to_inner());

    let witness_signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };

    key_spend_tx.input[0]
        .witness
        .push(witness_signature.to_vec());

    // Broadcast the transaction
    let txid = client.send_raw_transaction(&key_spend_tx).await?;
    Ok(txid)
}

struct TaprootKeySpendTest;

#[async_trait]
impl TestCase for TaprootKeySpendTest {
    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-fallbackfee=0.00001"],
            ..Default::default()
        }
    }

    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: false,
            ..Default::default()
        }
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let bitcoin_node = f.bitcoin_nodes.get(0).unwrap();
        let client = bitcoin_node.client();
        let network = Network::Regtest;

        let private_key = SecretKey::from_str(PROVER_DA_PRIVATE_KEY).unwrap();
        let public_key = bitcoin::secp256k1::XOnlyPublicKey::from_keypair(
            &bitcoin::key::UntweakedKeypair::from_secret_key(SECP256K1, &private_key),
        )
        .0;

        let unspent_list = client.list_unspent(None, None, None, None, None).await?;

        let unspent = unspent_list
            .into_iter()
            .find(|u| u.amount >= Amount::from_btc(1.0).unwrap())
            .ok_or_else(|| anyhow::anyhow!("No suitable UTXO found"))?;

        let change_address = unspent
            .address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("UTXO has no address"))?
            .clone()
            .assume_checked();

        let script_pubkey = unspent
            .address
            .as_ref()
            .map(|addr| {
                addr.clone()
                    .assume_checked()
                    .script_pubkey()
                    .to_hex_string()
            })
            .unwrap_or_default();

        let utxo = UTXO {
            tx_id: unspent.txid,
            vout: unspent.vout,
            address: unspent.address.map(|addr| addr.as_unchecked().clone()),
            script_pubkey,
            amount: unspent.amount.to_sat(),
            confirmations: unspent.confirmations as u32,
            spendable: unspent.spendable,
            solvable: unspent.solvable,
        };

        // Create a destination address for spending
        let destination_address = client
            .get_new_address(None, None)
            .await?
            .require_network(network)?;

        // test data for the inscription
        let test_data = b"test_inscription_data_for_taproot_key_spend";

        // Create inscription
        let inscription_txs = create_inscription_type_0(
            test_data.to_vec(),
            &private_key,
            None,
            vec![utxo.clone()],
            change_address.clone(),
            10, // commit fee rate
            10, // reveal fee rate
            network,
            &[],
        )?;

        let (commit_tx, reveal_tx) = match inscription_txs {
            DaTxs::Complete { commit, reveal } => (commit, reveal.tx),
            _ => return Err(anyhow::anyhow!("Expected Complete inscription type")),
        };

        let reveal_witness = &reveal_tx.input[0].witness;
        let reveal_script = ScriptBuf::from_bytes(reveal_witness.nth(1).unwrap().to_vec());

        let taproot_spend_info = bitcoin::taproot::TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone())
            .expect("Cannot add reveal script to taptree")
            .finalize(SECP256K1, public_key)
            .expect("Cannot finalize taptree");

        let merkle_root = taproot_spend_info.merkle_root();

        // Sign and send the commit transaction
        let signed_commit_tx = client
            .sign_raw_transaction_with_wallet(&commit_tx, None, None)
            .await?;

        let commit_txid = client
            .send_raw_transaction(&signed_commit_tx.transaction()?)
            .await?;

        // Mine a block to include the commit transaction
        bitcoin_node.generate(1).await.unwrap();

        // The vout is 0 since we're using the first output of the commit transaction
        let commit_vout = 0;
        let commit_amount = commit_tx.output[commit_vout].value;

        // Test key spend path to recover the locked funds
        let key_spend_txid = test_key_spend_recovery(
            client,
            &commit_tx,
            commit_vout, // commit output index
            &destination_address,
            &private_key,
            merkle_root,
        )
        .await?;

        bitcoin_node.generate(1).await.unwrap();

        // Verify the key spend transaction was mined
        let key_spend_info = client
            .get_raw_transaction_info(&key_spend_txid, None)
            .await?;

        assert!(
            key_spend_info.confirmations.unwrap_or(0) > 0,
            "Key spend recovery transaction not confirmed"
        );

        let key_spend_tx = client.get_raw_transaction(&key_spend_txid, None).await?;

        // Assert that the transaction spends from the commit transaction
        assert_eq!(key_spend_tx.input[0].previous_output.txid, commit_txid);

        // Assert that funds were sent to the destination address
        assert_eq!(
            key_spend_tx.output[0].script_pubkey,
            destination_address.script_pubkey(),
        );

        // Assert that the recovered amount minus fee is within (commit amount minus fee)
        let recovered_amount = key_spend_tx.output[0].value;
        let expected_min_amount = commit_amount - Amount::from_sat(2000); // commit amount minus reasonable fee
        assert!(recovered_amount >= expected_min_amount);

        Ok(())
    }
}

#[tokio::test]
async fn test_taproot_key_spend() -> Result<()> {
    TestCaseRunner::new(TaprootKeySpendTest).run().await
}
