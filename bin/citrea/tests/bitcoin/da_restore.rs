//! Restore of the DA transaction chain from wallet-visible transactions.
//!
//! Anyone can make an inscription of their own visible to a sequencer or a batch prover by
//! paying dust to one of its addresses, so restore has to treat what it finds as hostile input
//! and still come up with a chain the node can build on.

use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, Transaction};
use bitcoin_da::helpers::builders::test_utils::test_create_foreign_inscription;
use bitcoin_da::service::BitcoinService;
use bitcoin_da::spec::utxo::UTXO;
use bitcoincore_rpc::json::AddressType;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use citrea_e2e::bitcoin::BitcoinNode;
use citrea_e2e::config::{BitcoinConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::NodeKind;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::NodeT;
use citrea_e2e::Result;
use citrea_primitives::REVEAL_TX_PREFIX;
use reth_tasks::TaskManager;
use sov_rollup_interface::da::{DaTxRequest, SequencerCommitment};

use super::get_citrea_path;
use crate::bitcoin::utils::get_default_service;

/// Not one of the node's keys: the inscription is the attacker's own.
const ATTACKER_DA_PRIVATE_KEY: &str =
    "1212121212121212121212121212121212121212121212121212121212121212";
const ATTACKER_WALLET: &str = "da-restore-attacker";

struct DaRestoreWithHostileUtxosTest {
    task_manager: TaskManager,
}

impl DaRestoreWithHostileUtxosTest {
    /// Opens an RPC client on `wallet` of the DA node.
    async fn wallet_client(da: &BitcoinNode, wallet: &str) -> Result<Client> {
        let url = format!("http://127.0.0.1:{}/wallet/{wallet}", da.config.rpc_port);
        Ok(Client::new(
            &url,
            Auth::UserPass(da.config.rpc_user.clone(), da.config.rpc_password.clone()),
        )
        .await?)
    }

    /// Publishes a commit/reveal pair that the victim's wallet can see but did not create: the
    /// commit pays it change, and the reveal can either pay vout 0 to the victim or keep it for
    /// the attacker. Additional victim outputs exercise duplicate `list_unspent` entries.
    async fn publish_foreign_inscription(
        &self,
        da: &BitcoinNode,
        attacker: &Client,
        victim_address: &Address,
        victim_owns_vout_zero: bool,
        additional_victim_outputs: usize,
        confirm: bool,
    ) -> Result<Transaction> {
        let utxos: Vec<UTXO> = attacker
            .list_unspent(Some(1), None, None, None, None)
            .await?
            .into_iter()
            .map(Into::into)
            .collect();
        assert!(!utxos.is_empty(), "attacker wallet is not funded");

        let attacker_address = attacker
            .get_new_address(None, Some(AddressType::Bech32m))
            .await?
            .assume_checked();
        let reveal_recipient = if victim_owns_vout_zero {
            victim_address.clone()
        } else {
            attacker_address
        };

        let (commit, reveal) = test_create_foreign_inscription(
            vec![7u8; 1024],
            &SecretKey::from_str(ATTACKER_DA_PRIVATE_KEY).unwrap(),
            utxos,
            reveal_recipient,
            victim_address.clone(),
            additional_victim_outputs,
            1.0,
            1.0,
            bitcoin::Network::Regtest,
            REVEAL_TX_PREFIX,
        )
        .expect("Failed to build foreign inscription");

        // Only the commit inputs are the attacker's to sign; signing is witness-only, so the
        // txid the reveal already commits to is unchanged.
        let signed_commit = attacker
            .sign_raw_transaction_with_wallet(&commit, None, None)
            .await?;
        assert!(signed_commit.complete, "attacker could not sign its commit");

        attacker.send_raw_transaction(&signed_commit.hex).await?;
        attacker.send_raw_transaction(&reveal).await?;
        if confirm {
            da.generate(1).await?;
        }

        Ok(reveal)
    }
}

#[async_trait]
impl TestCase for DaRestoreWithHostileUtxosTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_sequencer: true,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-fallbackfee=0.00001"],
            ..Default::default()
        }
    }

    async fn cleanup(self) -> Result<()> {
        self.task_manager
            .graceful_shutdown_with_timeout(Duration::from_secs(1));
        Ok(())
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let task_executor = self.task_manager.executor();
        let da = f.bitcoin_nodes.get(0).unwrap();

        let victim = Self::wallet_client(da, &NodeKind::Bitcoin.to_string()).await?;
        let victim_address = victim.get_new_address(None, None).await?.assume_checked();

        da.client()
            .create_wallet(ATTACKER_WALLET, None, None, None, None)
            .await?;
        da.fund_wallet(ATTACKER_WALLET.to_string(), 5).await?;

        // Mature the attacker's coinbases so it can fund its own commit.
        da.generate(101).await?;
        let attacker = Self::wallet_client(da, ATTACKER_WALLET).await?;

        // Hostile pairs covering every restore predicate an attacker can satisfy without the
        // victim's DA key:
        // - with vout 0 and vout 1 both owned by the victim;
        // - with only a later output owned by the victim;
        // - an unconfirmed single-output reveal whose vout 0 is owned by the victim, which
        //   passes ownership and shape checks so only DA-key authentication rejects it.
        let duplicated_reveal = self
            .publish_foreign_inscription(da, &attacker, &victim_address, true, 1, true)
            .await?;
        let poisoning_reveal = self
            .publish_foreign_inscription(da, &attacker, &victim_address, false, 1, true)
            .await?;
        let rbf_reveal = self
            .publish_foreign_inscription(da, &attacker, &victim_address, true, 0, false)
            .await?;

        let unspent = victim.list_unspent(Some(0), None, None, None, None).await?;
        let duplicated_txid = duplicated_reveal.compute_txid();
        assert_eq!(
            unspent
                .iter()
                .filter(|utxo| utxo.txid == duplicated_txid)
                .count(),
            2,
            "the victim wallet should see the hostile reveal twice"
        );

        // Restore runs here, and panics if it errors: a hostile pair must not take startup down.
        let da_service: std::sync::Arc<BitcoinService> =
            get_default_service(&task_executor, &da.config).await;

        let monitored = da_service.monitoring.get_monitored_txs().await;
        for reveal in [&duplicated_reveal, &poisoning_reveal, &rbf_reveal] {
            assert!(
                !monitored.contains_key(&reveal.compute_txid()),
                "a reveal the wallet only witnessed was restored as part of our chain"
            );
        }

        // The tip must be something we can sign for, so publication keeps working.
        let txs = da_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(SequencerCommitment {
                    merkle_root: [1; 32],
                    index: 1,
                    l2_end_block_number: 10,
                }),
                1.0,
            )
            .await
            .expect("hostile UTXOs must not stall DA publication");

        let [commit, reveal] = &txs[0];
        for hostile in [&duplicated_reveal, &poisoning_reveal, &rbf_reveal] {
            assert_ne!(
                commit.tx.input[0].previous_output.txid,
                hostile.compute_txid(),
                "commit chained from a hostile reveal"
            );
        }
        // Publication is synchronous, so our pair is in the mempool by now. Assert on txids and
        // not on a mempool length, since the sequencer publishes to the same node.
        let mempool = da.get_raw_mempool().await?;
        for txid in [commit.id, reveal.id, rbf_reveal.compute_txid()] {
            assert!(
                mempool.contains(&txid),
                "{txid} is missing from the mempool"
            );
        }

        // A fresh service must still restore and chain from an honest unconfirmed reveal, which
        // guards the positive path of the DA-key check.
        let restarted_service = get_default_service(&task_executor, &da.config).await;
        let restored = restarted_service.monitoring.get_monitored_txs().await;
        assert!(restored.contains_key(&commit.id));
        assert!(restored.contains_key(&reveal.id));
        assert_eq!(
            restarted_service.monitoring.get_last_tx().await.unwrap().0,
            reveal.id
        );

        let chained_txs = restarted_service
            .send_transaction_with_fee_rate(
                DaTxRequest::SequencerCommitment(SequencerCommitment {
                    merkle_root: [2; 32],
                    index: 2,
                    l2_end_block_number: 20,
                }),
                1.0,
            )
            .await
            .expect("an honest restored reveal must remain a usable chain tip");
        assert_eq!(
            chained_txs[0][0].tx.input[0].previous_output.txid,
            reveal.id
        );
        let mempool = da.get_raw_mempool().await?;
        for txid in [chained_txs[0][0].id, chained_txs[0][1].id] {
            assert!(
                mempool.contains(&txid),
                "{txid} is missing from the mempool"
            );
        }

        Ok(())
    }
}

#[tokio::test]
async fn test_da_restore_with_hostile_utxos() -> Result<()> {
    TestCaseRunner::new(DaRestoreWithHostileUtxosTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}
