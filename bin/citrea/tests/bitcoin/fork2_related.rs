use std::net::SocketAddr;
use std::str::FromStr;

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy_primitives::{Address, Bytes, U256, U64};
use alloy_rpc_types::{Authorization, TransactionRequest};
use anyhow::Result;
use async_trait::async_trait;
use bitcoin_da::service::FINALITY_DEPTH;
use citrea_e2e::config::{SequencerConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::traits::NodeT;
use citrea_evm::smart_contracts::{
    G1AddCallerContract, KZGPointEvaluationCallerContract, P256VerifyCallerContract,
    SchnorrVerifyCallerContract, SimpleStorageContract,
};
use revm::bytecode::eip7702::Eip7702Bytecode;
use sha2::Digest;
use sov_ledger_rpc::LedgerRpcClient;

use crate::bitcoin::batch_prover_test::{wait_for_prover_job, wait_for_prover_job_count};
use crate::bitcoin::get_citrea_path;
use crate::common::make_test_client;

/// This is a basic prover test showcasing spawning a bitcoin node as DA, a sequencer and a prover.
/// It generates l2 blocks and wait until it reaches the first commitment.
/// It asserts that the blob inscribe txs have been sent.
/// This catches regression to the default prover flow, such as the one introduced by [#942](https://github.com/chainwayxyz/citrea/pull/942) and [#973](https://github.com/chainwayxyz/citrea/pull/973)
struct PrecompilesAndEip7702;

#[async_trait]
impl TestCase for PrecompilesAndEip7702 {
    fn test_config() -> TestCaseConfig {
        TestCaseConfig {
            with_batch_prover: true,
            with_full_node: true,
            ..Default::default()
        }
    }

    fn sequencer_config() -> SequencerConfig {
        SequencerConfig {
            max_l2_blocks_per_commitment: 100,
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

        let max_l2_blocks_per_commitment = sequencer.max_l2_blocks_per_commitment();

        let seq_test_client = make_test_client(SocketAddr::new(
            sequencer.config().rpc_bind_host().parse()?,
            sequencer.config().rpc_bind_port(),
        ))
        .await?;

        sequencer.client().send_publish_batch_request().await?;

        // Deploy simple storage contract
        let _deploy_tx = seq_test_client
            .deploy_contract(SimpleStorageContract::default().byte_code(), None)
            .await
            .unwrap();

        let delegate_to_address = seq_test_client.from_addr.create(0);

        // Deploy kzg caller contract
        let _deploy_tx = seq_test_client
            .deploy_contract(
                KZGPointEvaluationCallerContract::default().byte_code(),
                None,
            )
            .await
            .unwrap();

        let kzg_caller_address = seq_test_client.from_addr.create(1);

        // Deploy schnorr caller contract
        let _deploy_tx = seq_test_client
            .deploy_contract(SchnorrVerifyCallerContract::default().byte_code(), None)
            .await
            .unwrap();
        let schnorr_caller_address = seq_test_client.from_addr.create(2);

        // Deploy p256verify caller contract
        let _deploy_tx = seq_test_client
            .deploy_contract(P256VerifyCallerContract::default().byte_code(), None)
            .await
            .unwrap();
        let p256verify_caller_address = seq_test_client.from_addr.create(3);

        let _deploy_tx = seq_test_client
            .deploy_contract(G1AddCallerContract::default().byte_code(), None)
            .await
            .unwrap();
        let g1_add_caller_address = seq_test_client.from_addr.create(4);

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        sequencer.client.send_publish_batch_request().await?;

        let last_block = seq_test_client.eth_get_block_by_number(None).await;

        assert_eq!(last_block.transactions.len(), 5);

        // send eip7702 tx
        let authority_signer = PrivateKeySigner::random();
        let authorization = Authorization {
            address: delegate_to_address,
            chain_id: U256::from(seq_test_client.chain_id),
            nonce: 0,
        };
        let signature = authority_signer
            .sign_hash_sync(&authorization.signature_hash())
            .unwrap();
        let signed_authorization = authorization.into_signed(signature);

        let set_code_tx = seq_test_client
            .send_eip7702_transaction(Address::ZERO, vec![], None, vec![signed_authorization])
            .await?;

        // send tx to kzg caller

        // Implementation taken from https://eips.ethereum.org/EIPS/eip-4844#point-evaluation-precompile
        fn kzg_to_versioned_hash(commitment: Bytes) -> Bytes {
            let mut commitment_hash = sha2::Sha256::digest(commitment).to_vec();
            commitment_hash[0] = 1;
            Bytes::from(commitment_hash)
        }

        // data is taken from: https://github.com/ethereum/c-kzg-4844/tree/main/tests/verify_kzg_proof/kzg-mainnet/verify_kzg_proof_case_correct_proof_d0992bc0387790a4
        let commitment= Bytes::from_str("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7").unwrap();
        let versioned_hash = kzg_to_versioned_hash(commitment.clone());
        let z = Bytes::from_str("5eb7004fe57383e6c88b99d839937fddf3f99279353aaf8d5c9a75f91ce33c62")
            .unwrap();
        let y = Bytes::from_str("4882cf0609af8c7cd4c256e63a35838c95a9ebbf6122540ab344b42fd66d32e1")
            .unwrap();
        let proof =  Bytes::from_str("0x987ea6df69bbe97c23e0dd948cf2d4490824ba7fea5af812721b2393354b0810a9dba2c231ea7ae30f26c412c7ea6e3a").unwrap();

        // The data is encoded as follows: versioned_hash | z | y | commitment | proof | with z and y being padded 32 byte big endian values
        // ref: https://eips.ethereum.org/EIPS/eip-4844#point-evaluation-precompile
        let mut input = vec![];
        input.extend_from_slice(&versioned_hash);
        input.extend_from_slice(&z);
        input.extend_from_slice(&y);
        input.extend_from_slice(&commitment);
        input.extend_from_slice(&proof);

        let kzg_call = seq_test_client
            .contract_transaction(
                kzg_caller_address,
                KZGPointEvaluationCallerContract::default().call_kzg_point_evaluation(input.into()),
                None,
            )
            .await;

        // send tx to schnorr caller
        let input = Bytes::from_str("0xD69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B94DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B969670300000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4").unwrap();

        let schnorr_call = seq_test_client
            .contract_transaction(
                schnorr_caller_address,
                SchnorrVerifyCallerContract::default().call_schnorr_verify(input),
                None,
            )
            .await;

        // send tx to p256verify caller
        let input = Bytes::from_str("b5a77e7a90aa14e0bf5f337f06f597148676424fae26e175c6e5621c34351955289f319789da424845c9eac935245fcddd805950e2f02506d09be7e411199556d262144475b1fa46ad85250728c600c53dfd10f8b3f4adf140e27241aec3c2da3a81046703fccf468b48b145f939efdbb96c3786db712b3113bb2488ef286cdcef8afe82d200a5bb36b5462166e8ce77f2d831a52ef2135b2af188110beaefb1").unwrap();

        let p256_call = seq_test_client
            .contract_transaction(
                p256verify_caller_address,
                P256VerifyCallerContract::default().call_p256_verify(input),
                None,
            )
            .await;

        let input = Bytes::from_str("0x0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e100000000000000000000000000000000112b98340eee2777cc3c14163dea3ec97977ac3dc5c70da32e6e87578f44912e902ccef9efe28d4a78b8999dfbca942600000000000000000000000000000000186b28d92356c4dfec4b5201ad099dbdede3781f8998ddf929b4cd7756192185ca7b8f4ef7088f813270ac3d48868a21").unwrap();
        let g1_add_call = seq_test_client
            .contract_transaction(
                g1_add_caller_address,
                G1AddCallerContract::default().call_g1_add(input),
                None,
            )
            .await;

        // publish block and make necessary assertions
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        sequencer.client.send_publish_batch_request().await?;

        let last_block = seq_test_client.eth_get_block_by_number(None).await;
        assert_eq!(last_block.transactions.len(), 5);

        // authority should have code
        assert!(set_code_tx.get_receipt().await.unwrap().status());
        let authority_code = seq_test_client
            .eth_get_code(authority_signer.address(), None)
            .await
            .unwrap();

        assert_eq!(
            authority_code,
            *Eip7702Bytecode::new(delegate_to_address).raw()
        );

        // all precompile call txs succeeded
        assert!(kzg_call.get_receipt().await.unwrap().status());
        assert_ne!(
            seq_test_client
                .eth_get_storage_at(kzg_caller_address, U256::ZERO, None)
                .await
                .unwrap(),
            U256::from_str(
                "52435875175126190479447740508185965837690552500527637822603658699938581184513"
            )
            .unwrap()
        );

        assert!(schnorr_call.get_receipt().await.unwrap().status());
        assert_eq!(
            seq_test_client
                .eth_get_storage_at(schnorr_caller_address, U256::ZERO, None)
                .await
                .unwrap(),
            U256::from(1)
        );

        assert!(p256_call.get_receipt().await.unwrap().status());
        assert_eq!(
            seq_test_client
                .eth_get_storage_at(p256verify_caller_address, U256::ZERO, None)
                .await
                .unwrap(),
            U256::from(1)
        );

        assert!(g1_add_call.get_receipt().await.unwrap().status());
        assert_eq!(
            seq_test_client
                .client.call(TransactionRequest::default().to(g1_add_caller_address).input(G1AddCallerContract::default().get_result().into())).await.unwrap(),
            // encoding of example input's result
            Bytes::from_str("0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000a40300ce2dec9888b60690e9a41d3004fda4886854573974fab73b046d3147ba5b7a5bde85279ffede1b45b3918d82d0000000000000000000000000000000006d3d887e9f53b9ec4eb6cedf5607226754b07c01ace7834f57f3e7315faefb739e59018e22c492006190fba4a870025").unwrap()
        );

        let set_storage_tx = seq_test_client
            .contract_transaction(
                authority_signer.address(),
                SimpleStorageContract::default().set_call_data(11),
                None,
            )
            .await;

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        sequencer.client.send_publish_batch_request().await?;

        assert!(set_storage_tx.get_receipt().await.unwrap().status());

        assert_eq!(
            seq_test_client
                .eth_get_storage_at(authority_signer.address(), U256::ZERO, None)
                .await
                .unwrap(),
            U256::from(11)
        );

        // force a sequencer commitment
        let cur_block_number = seq_test_client
            .ledger_get_head_l2_block_height()
            .await
            .unwrap();

        assert!(cur_block_number < max_l2_blocks_per_commitment);

        let needed = max_l2_blocks_per_commitment - cur_block_number + 1;

        for _ in 0..needed {
            sequencer.client.send_publish_batch_request().await?;
        }

        // wait for the commitment to be published
        da.wait_mempool_len(2, None).await?;

        da.generate(FINALITY_DEPTH).await?;

        let finalized_height = da.get_finalized_height(Some(FINALITY_DEPTH)).await?;

        // wait for batch prover to see commitments
        batch_prover
            .wait_for_l1_height(finalized_height, None)
            .await
            .unwrap();

        let job_ids = wait_for_prover_job_count(batch_prover, 1, None)
            .await
            .unwrap();
        assert_eq!(job_ids.len(), 1);

        let response = wait_for_prover_job(batch_prover, job_ids[0], None)
            .await
            .unwrap();
        let proof = response.proof.unwrap();

        let state_root = full_node
            .client
            .http_client()
            .get_l2_block_by_number(proof.proof_output.last_l2_height)
            .await?
            .unwrap()
            .header
            .state_root;

        assert!(proof.proof_output.final_state_root() == state_root);

        let state_root = sequencer
            .client
            .http_client()
            .get_l2_block_by_number(proof.proof_output.last_l2_height)
            .await?
            .unwrap()
            .header
            .state_root;
        assert!(proof.proof_output.final_state_root() == state_root);

        assert!(proof.proof_output.last_l2_height > U64::from(cur_block_number));

        Ok(())
    }
}

#[tokio::test]
async fn precompiles_and_eip7702_test() -> Result<()> {
    TestCaseRunner::new(PrecompilesAndEip7702)
        .set_citrea_path(get_citrea_path())
        .run()
        .await
}
