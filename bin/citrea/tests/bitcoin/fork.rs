use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use alloy::signers::SignerSync;
use alloy_primitives::{Address, Bytes, U256, U64};
use async_trait::async_trait;
use citrea_e2e::bitcoin::{BitcoinNode, DEFAULT_FINALITY_DEPTH};
use citrea_e2e::config::{CitreaMode, SequencerConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::node::Sequencer;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::NodeT;
use citrea_e2e::Result;
use citrea_evm::smart_contracts::{
    G1AddCallerContract, P256VerifyCallerContract, SchnorrVerifyCallerContract,
    SimpleStorageContract,
};
use citrea_primitives::forks::{get_forks, use_network_forks};
use sov_ledger_rpc::LedgerRpcClient;
use sov_rollup_interface::Network;

use super::batch_prover_test::wait_for_zkproofs;
use super::get_citrea_path;
use crate::common::client::TestClient;
use crate::common::make_test_client;

struct ForkActivationTest;

const SCHNORR_INPUT: &str = "0xD69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B94DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B969670300000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4";
const P256_INPUT: &str = "b5a77e7a90aa14e0bf5f337f06f597148676424fae26e175c6e5621c34351955289f319789da424845c9eac935245fcddd805950e2f02506d09be7e411199556d262144475b1fa46ad85250728c600c53dfd10f8b3f4adf140e27241aec3c2da3a81046703fccf468b48b145f939efdbb96c3786db712b3113bb2488ef286cdcef8afe82d200a5bb36b5462166e8ce77f2d831a52ef2135b2af188110beaefb1";
const G1_ADD_INPUT: &str = "0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e100000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca942600000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a21";

#[async_trait]
impl TestCase for ForkActivationTest {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            mode: CitreaMode::DevAllForks,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 15,
            ..Default::default()
        }
    }

    fn scan_l1_start_height() -> Option<u64> {
        Some(170)
    }

    async fn run_test(&mut self, f: &mut TestFramework) -> Result<()> {
        let da = f.bitcoin_nodes.get(0).unwrap();
        let sequencer = f.sequencer.as_ref().unwrap();
        let batch_prover = f.batch_prover.as_ref().unwrap();
        let full_node = f.full_node.as_ref().unwrap();

        println!("Running with forks : {:?}", get_forks());
        let kumquat_height = get_forks()[1].activation_height;
        let tangerine_height = get_forks()[2].activation_height;

        let seq_test_client = make_test_client(SocketAddr::new(
            sequencer.config().rpc_bind_host().parse()?,
            sequencer.config().rpc_bind_port(),
        ))
        .await
        .unwrap();

        let contracts = self
            .deploy_test_contracts(sequencer, &seq_test_client)
            .await
            .unwrap();

        self.test_pre_kumquat(sequencer, da, &seq_test_client, &contracts)
            .await
            .unwrap();

        self.advance_to_kumquat(sequencer, kumquat_height)
            .await
            .unwrap();

        self.test_kumquat_features(sequencer, da, &seq_test_client, &contracts)
            .await
            .unwrap();

        self.advance_to_tangerine(sequencer, tangerine_height)
            .await
            .unwrap();

        self.test_tangerine_features(sequencer, &seq_test_client, &contracts)
            .await
            .unwrap();

        self.verify_sequencer_commitment(sequencer, da, batch_prover, full_node, tangerine_height)
            .await
            .unwrap();

        Ok(())
    }
}

struct TestContracts {
    schnorr_caller: Address,
    p256_caller: Address,
    g1_add_caller: Address,
}

impl ForkActivationTest {
    async fn deploy_test_contracts(
        &self,
        sequencer: &Sequencer,
        client: &TestClient,
    ) -> Result<TestContracts> {
        // Deploy simple storage contract
        let _deploy_tx = client
            .deploy_contract(SimpleStorageContract::default().byte_code(), None)
            .await
            .unwrap();

        let _ = client
            .deploy_contract(SchnorrVerifyCallerContract::default().byte_code(), None)
            .await
            .unwrap();
        let schnorr_caller = client.from_addr.create(1);

        let _ = client
            .deploy_contract(P256VerifyCallerContract::default().byte_code(), None)
            .await
            .unwrap();
        let p256_caller = client.from_addr.create(2);

        let _ = client
            .deploy_contract(G1AddCallerContract::default().byte_code(), None)
            .await
            .unwrap();
        let g1_add_caller = client.from_addr.create(3);

        tokio::time::sleep(Duration::from_secs(1)).await;
        sequencer.client.send_publish_batch_request().await?;
        sequencer.wait_for_l2_height(1, None).await?;

        let contracts = TestContracts {
            schnorr_caller,
            p256_caller,
            g1_add_caller,
        };

        Ok(contracts)
    }

    async fn test_pre_kumquat(
        &self,
        sequencer: &Sequencer,
        da: &BitcoinNode,
        client: &TestClient,
        contracts: &TestContracts,
    ) -> Result<()> {
        let height = sequencer.client.ledger_get_head_l2_block_height().await?;
        println!("Running test_pre_kumquat at height {height}");
        {
            let schnorr_input = Bytes::from_str(SCHNORR_INPUT).unwrap();
            let schnorr_result = client
                .contract_call::<String>(
                    contracts.schnorr_caller,
                    SchnorrVerifyCallerContract::default()
                        .call_schnorr_verify(schnorr_input.clone()),
                    None,
                )
                .await;
            assert!(
                schnorr_result.is_err(),
                "Schnorr shouldn't be available in genesis"
            );
        }

        let eip7702_result = self.send_eip7702_transaction_and_get_code(client).await;
        assert!(
            eip7702_result.is_err(),
            "eip7702 tx shouldn't be available in genesis"
        );

        // Generate max_l2_blocks_per_commitment l2 blocks but make sure no commitment are send before tangerine
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        assert!(da
            .wait_mempool_len(2, Some(Duration::from_secs(5)))
            .await
            .is_err());

        Ok(())
    }

    async fn advance_to_kumquat(&self, sequencer: &Sequencer, kumquat_height: u64) -> Result<()> {
        let current_height = sequencer.client.ledger_get_head_l2_block_height().await?;

        if current_height >= kumquat_height {
            return Ok(());
        }

        for _ in current_height..kumquat_height {
            sequencer.client.send_publish_batch_request().await?;

            if sequencer.client.ledger_get_head_l2_block_height().await? >= kumquat_height {
                break;
            }
        }

        sequencer.wait_for_l2_height(kumquat_height, None).await
    }

    async fn test_kumquat_features(
        &self,
        sequencer: &Sequencer,
        da: &BitcoinNode,
        client: &TestClient,
        contracts: &TestContracts,
    ) -> Result<()> {
        let height = sequencer.client.ledger_get_head_l2_block_height().await?;
        println!("Running test_kumquat_features at height {height}");
        // Test schnoor in Kumquat
        {
            let input = Bytes::from_str(SCHNORR_INPUT).unwrap();
            let schnorr_result = client
                .contract_call::<String>(
                    contracts.schnorr_caller,
                    SchnorrVerifyCallerContract::default().call_schnorr_verify(input.clone()),
                    None,
                )
                .await;

            assert!(
                schnorr_result.is_err(),
                "Schnorr shouldn't be available after Kumquat fork"
            );
        }

        // Test p256 in Kumquat
        {
            let input = Bytes::from_str(P256_INPUT).unwrap();
            let p256_result = client
                .contract_call::<String>(
                    contracts.p256_caller,
                    P256VerifyCallerContract::default().call_p256_verify(input.clone()),
                    None,
                )
                .await;

            assert!(
                p256_result.is_err(),
                "P256_VERIFY precompile should not be available before Tangerine fork"
            );
        }

        let eip7702_result = self.send_eip7702_transaction_and_get_code(client).await;
        assert!(
            eip7702_result.is_err(),
            "eip7702 tx should fail before Tangerine fork"
        );

        // Generate max_l2_blocks_per_commitment l2 blocks but make sure no commitment are send before tangerine
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        assert!(da
            .wait_mempool_len(2, Some(Duration::from_secs(5)))
            .await
            .is_err());

        Ok(())
    }

    async fn advance_to_tangerine(
        &self,
        sequencer: &citrea_e2e::node::Sequencer,
        tangerine_height: u64,
    ) -> Result<()> {
        let current_height = sequencer.client.ledger_get_head_l2_block_height().await?;

        if current_height >= tangerine_height {
            return Ok(());
        }

        for _ in current_height..tangerine_height {
            sequencer.client.send_publish_batch_request().await?;

            if sequencer.client.ledger_get_head_l2_block_height().await? >= tangerine_height {
                break;
            }
        }

        sequencer.wait_for_l2_height(tangerine_height, None).await
    }

    async fn test_tangerine_features(
        &self,
        sequencer: &Sequencer,
        client: &TestClient,
        contracts: &TestContracts,
    ) -> Result<()> {
        let height = sequencer.client.ledger_get_head_l2_block_height().await?;
        println!("Running test_tangerine_features at height {height}");

        client.sync_nonce().await; // sync nonce because of failed pre-tangerine txs

        // Test that SCHNORR_VERIFY is available post Tangerine
        {
            let schnorr_input = Bytes::from_str(SCHNORR_INPUT).unwrap();
            let schnorr_tx = client
                .contract_transaction(
                    contracts.schnorr_caller,
                    SchnorrVerifyCallerContract::default()
                        .call_schnorr_verify(schnorr_input.clone()),
                    None,
                )
                .await;
            sequencer.client.send_publish_batch_request().await.unwrap();
            let receipt = schnorr_tx.get_receipt().await.unwrap();
            assert!(receipt.status());

            let storage = client
                .eth_get_storage_at(contracts.schnorr_caller, U256::ZERO, None)
                .await
                .unwrap();
            assert_eq!(storage, U256::from(1));

            let schnorr_call = client
                .contract_call::<String>(
                    Address::from_str("0x0000000000000000000000000000000000000200").unwrap(),
                    schnorr_input.to_vec(),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(
                schnorr_call,
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            );
        }

        // Test that P256_VERIFY is available post Tangerine
        {
            let p256_input = Bytes::from_str(P256_INPUT).unwrap();
            let p256_tx = client
                .contract_transaction(
                    contracts.p256_caller,
                    P256VerifyCallerContract::default().call_p256_verify(p256_input.clone()),
                    None,
                )
                .await;
            sequencer.client.send_publish_batch_request().await.unwrap();
            let receipt = p256_tx.get_receipt().await.unwrap();
            assert!(receipt.status(), "P256 tx should succeed in Tangerine");

            let p256_storage = client
                .eth_get_storage_at(contracts.p256_caller, U256::ZERO, None)
                .await
                .unwrap();
            assert_eq!(p256_storage, U256::from(1), "P256 storage should be 1");

            let p256_call = client
                .contract_call::<String>(
                    Address::from_str("0x0000000000000000000000000000000000000100").unwrap(),
                    p256_input.to_vec(),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(
                p256_call,
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            );
        }

        {
            let g1_add_input = Bytes::from_str(G1_ADD_INPUT).unwrap();
            let g1_add_tx = client
                .contract_transaction(
                    contracts.g1_add_caller,
                    G1AddCallerContract::default().call_g1_add(g1_add_input.clone()),
                    None,
                )
                .await;
            sequencer.client.send_publish_batch_request().await.unwrap();
            let receipt = g1_add_tx.get_receipt().await.unwrap();
            assert!(receipt.status(), "G1Add tx should succeed in Tangerine");

            let g1_add_result = client
                .contract_call::<String>(
                    contracts.g1_add_caller,
                    G1AddCallerContract::default().get_result(),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(
                g1_add_result,
                "0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000a40300ce2dec9888b60690e9a41d3004fda4886854573974fab73b046d3147ba5b7a5bde85279ffede1b45b3918d82d0000000000000000000000000000000006d3d887e9f53b9ec4eb6cedf5607226754b07c01ace7834f57f3e7315faefb739e59018e22c492006190fba4a870025"
            );

            let g1_add_call = client
                .contract_call::<String>(
                    Address::from_str("0x000000000000000000000000000000000000000b").unwrap(),
                    g1_add_input.to_vec(),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(
                g1_add_call,
                "0x000000000000000000000000000000000a40300ce2dec9888b60690e9a41d3004fda4886854573974fab73b046d3147ba5b7a5bde85279ffede1b45b3918d82d0000000000000000000000000000000006d3d887e9f53b9ec4eb6cedf5607226754b07c01ace7834f57f3e7315faefb739e59018e22c492006190fba4a870025"
            );
        }

        let eip7702_result = self.send_eip7702_transaction_and_get_code(client).await;
        assert!(
            eip7702_result.is_ok(),
            "eip7702 tx should succeed after Tangerine"
        );

        Ok(())
    }

    async fn send_eip7702_transaction_and_get_code(&self, client: &TestClient) -> Result<Bytes> {
        let authority_signer = alloy::signers::local::PrivateKeySigner::random();
        let delegate_to_address = client.from_addr.create(0);

        let authorization = alloy_rpc_types::Authorization {
            address: delegate_to_address,
            chain_id: alloy_primitives::U256::from(client.chain_id),
            nonce: 0,
        };

        let signature = authority_signer
            .sign_hash_sync(&authorization.signature_hash())
            .unwrap();

        let signed_authorization = authorization.into_signed(signature);

        let tx = client
            .send_eip7702_transaction(
                alloy_primitives::Address::ZERO,
                vec![],
                None,
                vec![signed_authorization],
            )
            .await?;

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        client.send_publish_batch_request().await;

        let receipt = tx.get_receipt().await.unwrap();
        assert!(receipt.status());

        client.eth_get_code(authority_signer.address(), None).await
    }

    async fn verify_sequencer_commitment(
        &self,
        sequencer: &Sequencer,
        da: &BitcoinNode,
        batch_prover: &citrea_e2e::node::BatchProver,
        full_node: &citrea_e2e::node::FullNode,
        tangerine_height: u64,
    ) -> Result<()> {
        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();
        for _ in 0..max_l2_blocks_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let finalized_height = da.get_finalized_height(None).await?;

        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await?;

        da.wait_mempool_len(2, None).await?;

        da.generate(DEFAULT_FINALITY_DEPTH).await?;
        let batch_proof_l1_height = da.get_finalized_height(None).await?;

        full_node
            .wait_for_l1_height(batch_proof_l1_height, None)
            .await?;

        let proof =
            &wait_for_zkproofs(full_node, batch_proof_l1_height, None, 1).await?[0].proof_output;

        assert!(
            proof.last_l2_height.to::<u64>() >= tangerine_height,
            "First proof should be after Tangerine fork"
        );

        let commitments = full_node
            .client
            .http_client()
            .get_sequencer_commitments_on_slot_by_number(U64::from(finalized_height))
            .await?
            .unwrap();

        assert_eq!(commitments.len(), 1);
        let commitment = &commitments[0];

        assert!(
            commitment.l2_end_block_number.to::<u64>() > tangerine_height,
            "First commitment should be after Tangerine fork"
        );
        assert_eq!(commitment.index.to::<u32>(), 1);

        Ok(())
    }
}

#[tokio::test]
async fn test_fork_activation() -> Result<()> {
    use_network_forks(Network::TestNetworkWithForks);

    TestCaseRunner::new(ForkActivationTest)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
