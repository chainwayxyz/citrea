use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, Transaction, TxMerkleNode, WitnessMerkleNode};
use bitcoin_da::helpers::parsers::{
    parse_batch_proof_transaction, parse_hex_transaction, parse_light_client_transaction,
    ParsedBatchProofTransaction, ParsedLightClientTransaction, VerifyParsed,
};
use bitcoin_da::service::{BitcoinService, BitcoinServiceConfig};
use bitcoin_da::spec::blob::BlobWithSender;
use bitcoin_da::spec::block::BitcoinBlock;
use bitcoin_da::spec::header::HeaderWrapper;
use bitcoin_da::spec::transaction::TransactionWrapper;
use bitcoin_da::spec::RollupParams;
use bitcoincore_rpc::RpcApi;
use citrea_common::tasks::manager::TaskManager;
use citrea_e2e::bitcoin::BitcoinNode;
use citrea_e2e::config::BitcoinConfig;
use citrea_e2e::node::NodeKind;
use citrea_e2e::traits::NodeT;
use citrea_primitives::compression::decompress_blob;
use citrea_primitives::{MAX_TXBODY_SIZE, TO_BATCH_PROOF_PREFIX, TO_LIGHT_CLIENT_PREFIX};
use sov_rollup_interface::da::{DaData, SequencerCommitment};
use sov_rollup_interface::services::da::DaService;

pub const DEFAULT_DA_PRIVATE_KEY: &str =
    "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262";

pub async fn get_default_service(
    task_manager: &mut TaskManager<()>,
    config: &BitcoinConfig,
) -> Arc<BitcoinService> {
    get_service(
        task_manager,
        config,
        NodeKind::Bitcoin.to_string(),
        DEFAULT_DA_PRIVATE_KEY.to_string(),
        TO_BATCH_PROOF_PREFIX.to_vec(),
        TO_LIGHT_CLIENT_PREFIX.to_vec(),
    )
    .await
}

pub async fn get_service(
    task_manager: &mut TaskManager<()>,
    config: &BitcoinConfig,
    wallet: String,
    da_private_key: String,
    to_batch_proof_prefix: Vec<u8>,
    to_light_client_prefix: Vec<u8>,
) -> Arc<BitcoinService> {
    let node_url = format!("http://127.0.0.1:{}/wallet/{}", config.rpc_port, wallet,);

    let runtime_config = BitcoinServiceConfig {
        node_url,
        node_username: config.rpc_user.clone(),
        node_password: config.rpc_password.clone(),
        network: bitcoin::Network::Regtest,
        da_private_key: Some(da_private_key),
        tx_backup_dir: get_tx_backup_dir(),
        monitoring: None,
    };

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

    let da_service = BitcoinService::new_without_wallet_check(
        runtime_config,
        RollupParams {
            to_batch_proof_prefix,
            to_light_client_prefix,
        },
        tx,
    )
    .await
    .expect("Error initializing BitcoinService");

    let da_service = Arc::new(da_service);
    task_manager.spawn(|tk| da_service.clone().run_da_queue(rx, tk));

    da_service
}

/// Generates mock commitment and zk proof transactions and publishes a DA block
/// with all mock transactions in it, and returns the block, valid commitments and proofs.
/// Transactions also contain invalid commitment and zk proof transactions.
///
/// In total it generates 28 transactions.
/// - Valid commitments: 3 (6 txs)
/// - Valid complete proofs: 2 (4 txs)
/// - Valid chunked proofs: 1 with 2 chunks (6 txs) + 1 with 3 chunks (8 txs)
/// - Invalid commitment with wrong public key: 1 (2 txs)
/// - Invalid commitment with wrong prefix: 1 (2 txs)
///
/// With coinbase transaction, returned block has total of 29 transactions.
pub async fn generate_mock_txs(
    da_service: &BitcoinService,
    da_node: &BitcoinNode,
    task_manager: &mut TaskManager<()>,
) -> (BitcoinBlock, Vec<SequencerCommitment>, Vec<Vec<u8>>) {
    // Funding wallet requires block generation, hence we do funding at the beginning
    // to be able to write all transactions into the same block.
    let wrong_prefix_wallet = "wrong_prefix".to_string();
    create_and_fund_wallet(wrong_prefix_wallet.clone(), da_node).await;
    let wrong_prefix_da_service = get_service(
        task_manager,
        &da_node.config,
        wrong_prefix_wallet,
        DEFAULT_DA_PRIVATE_KEY.to_string(),
        vec![5],
        vec![6],
    )
    .await;

    let wrong_key_wallet = "wrong_key".to_string();
    create_and_fund_wallet(wrong_key_wallet.clone(), da_node).await;
    let wrong_key_da_service = get_service(
        task_manager,
        &da_node.config,
        wrong_key_wallet,
        "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33263".to_string(),
        TO_BATCH_PROOF_PREFIX.to_vec(),
        TO_LIGHT_CLIENT_PREFIX.to_vec(),
    )
    .await;

    // Generate 100 blocks for wallets to get their rewards
    finalize_funds(da_node).await;

    let mut valid_commitments = vec![];
    let mut valid_proofs = vec![];

    let commitment = SequencerCommitment {
        merkle_root: [13; 32],
        l2_start_block_number: 1002,
        l2_end_block_number: 1100,
    };
    valid_commitments.push(commitment.clone());
    da_service
        .send_transaction(DaData::SequencerCommitment(commitment))
        .await
        .expect("Failed to send transaction");

    let commitment = SequencerCommitment {
        merkle_root: [14; 32],
        l2_start_block_number: 1101,
        l2_end_block_number: 1245,
    };
    valid_commitments.push(commitment.clone());
    da_service
        .send_transaction(DaData::SequencerCommitment(commitment))
        .await
        .expect("Failed to send transaction");

    let size = 2000;
    let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    valid_proofs.push(blob.clone());
    da_service
        .send_transaction(DaData::ZKProof(blob))
        .await
        .expect("Failed to send transaction");

    // Invoke chunked zk proof generation with 2 chunks
    let size = MAX_TXBODY_SIZE + 1500;
    let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    valid_proofs.push(blob.clone());
    da_service
        .send_transaction(DaData::ZKProof(blob))
        .await
        .expect("Failed to send transaction");

    // Sequencer commitment with wrong tx prefix
    wrong_prefix_da_service
        .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
            merkle_root: [15; 32],
            l2_start_block_number: 1246,
            l2_end_block_number: 1268,
        }))
        .await
        .expect("Failed to send transaction");

    let size = 1024;
    let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    valid_proofs.push(blob.clone());
    da_service
        .send_transaction(DaData::ZKProof(blob))
        .await
        .expect("Failed to send transaction");

    // Sequencer commitment with wrong key and signature
    wrong_key_da_service
        .send_transaction(DaData::SequencerCommitment(SequencerCommitment {
            merkle_root: [15; 32],
            l2_start_block_number: 1246,
            l2_end_block_number: 1268,
        }))
        .await
        .expect("Failed to send transaction");

    let commitment = SequencerCommitment {
        merkle_root: [15; 32],
        l2_start_block_number: 1246,
        l2_end_block_number: 1268,
    };
    valid_commitments.push(commitment.clone());
    da_service
        .send_transaction(DaData::SequencerCommitment(commitment))
        .await
        .expect("Failed to send transaction");

    // Invoke chunked zk proof generation with 3 chunks
    let size = MAX_TXBODY_SIZE * 2 + 2500;
    let blob = (0..size).map(|_| rand::random::<u8>()).collect::<Vec<u8>>();

    valid_proofs.push(blob.clone());
    da_service
        .send_transaction(DaData::ZKProof(blob))
        .await
        .expect("Failed to send transaction");

    // Write all txs to a block
    let block_hash = da_node.generate(1).await.unwrap()[0];

    let block = da_service.get_block_by_hash(block_hash).await.unwrap();
    assert_eq!(block.txdata.len(), 29);

    (block, valid_commitments, valid_proofs)
}

#[allow(unused)]
pub fn get_mock_nonsegwit_block() -> BitcoinBlock {
    // There are no relevant txs
    // txs[2] is a non-segwit tx but its txid has the prefix 00
    let txs = [
        "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0f048bdb051a02e503062f503253482fffffffff0140e10d2a01000000434104808df9f502a2f1a2dd1848bade4be111b9f2e66d5c4bd6b9f1682b4d04a53bdb052ebb91ae056dc8a3cd59545265947ee61d54c49aa81981d550bf7f9167ef12ac00000000",
        "01000000016a5aa0c54e24722d2cd6be99c26b3729fae9b7c27c851b080aa45c5b47c26d2d010000008a47304402201c9404cd4a8b21509834fafff15d700788ffaa842f760e1ab1dc173fa2676ec202202c7e77ad14e48320a272952db318f9f968bcefcf50123f0f40db410d6cd300bc01410491d63a7c33798ca1da6a88ea5cd8daf9c33190571ca4738306b8848466b8494619a0d217a39d4bb0c929735f9c4a1c0dea074239e153b81b9b7cfc85dd36faf8ffffffff0200ec6021000000001976a9146c11a5e60863b35f85d3911920a1aecf11f7153988ac40a8f527000000001976a914ccaf060b633fe6b1f43e2ecc8e0f17adf09d534c88ac00000000",
        "01000000013377c58db37da73db2c3a269ddf410251073673983790ab5426e215f323ce00f010000008c493046022100fa6a7c25870c377080c1b5b42d216d501ac971ac09507ce079bdaf6da5b046ec022100fa885eef30ffa7a8768a30a5faac6cace724851cd53806413b10aec060bc274a0141049a162e57d5e0f96374f8ead29937ab5a90385f07678b159da4f57cb87b646c148f56a870fb779a9037fabf5fdacc753b34eb98d49e300c36e9b0f3873194e759ffffffff02002d3101000000001976a91406f1b66ffe49df7fce684df16c62f59dc9adbd3f88ac90762907000000001976a9144ef9f0e7ad583d773495722dd79ec11188b9e4fd88ac00000000",
        "0100000001c9e1effb36254352bca658cfc7b06d6d358cbbffda74dc1c6fb7e25ff3fde256010000008c493046022100d871f859bf9cc2be5080194ed0c38e977e83c212be7150d7d0b65a7704bd830f022100e27f5d8922d7d977b690386457f7fb9c714241ab9d7b91bf05fbac68f2dc69b001410449f6c65c3ba451e4891f8e51e46580c7fcb87480bf5aa2f9d47644ff7b692cfa801d95f6980cef95fb49b3ec42c6ff4ed289d948f03c7f409b34647d0fedf803ffffffff0220651100000000001976a914d0b79214b73d2cba68b524ae1c0f102771e7551c88aca016f912000000001976a9142af648c077286a6c1233eb190bcd767478ced70d88ac00000000",
        "01000000020792275b6ad62da82d98eaebb5de782642a06c92a80872c2cb3354da52c1ba2e000000008b483045022100fdc067f20ee84e3a4aea25638eb125b44376555ffbdd0fa05611a27a55d2610f022009b3c111bffae5e517bf957bd3f53a3306a6b5c5725418955f20afb6fbd1bb380141048cc0b94178715f03ed3d0bceb368191d0fdd7fc16d806567f6f2c45aecafb8f53e5ef849564072189b9b4f8bfe1564da776567ba359cfb0c05e839bcf65371abffffffff2316672bbcf879e3a96a2e8aab283b44529c4eec8fed798e5e435011c2b5059b010000008b48304502204caab3248930be319ba445c44398aa94e0032dfd25456d09ccd2b076737ef2f6022100eb460ca09390a67b8195fad6c4d0563d243b824ece6bafb69d21ca30542cfaa5014104952fe2d53debd645dffac11367b3888a9e5465eb9c150b98a504d7f8d4c3e98c1a6876175be17462d163e6015ce12c9c2b0a3629e1371e247109222d0b8ed5dbffffffff0230578d09000000001976a9144ef9f0e7ad583d773495722dd79ec11188b9e4fd88ac18366704000000001976a914b4f5b5a9e5119d3f0327d4ff64a1b0a97fc423d988ac00000000",
        "01000000019ac1695d2e613e3bee66317bbd9ad8ec4033f596ce5c43691837e8322b3a8112010000008c49304602210083a64c8ff430ac05376ab5f940d7801796d6dd0687922af2c8f7247368a41f56022100d55326fdc50a70d992f0a04ef19e5d8edc244941d9976d609ab1b6c1ed2e92760141046992f8f0bdde46834e24df367c28233501fa8615ada18c84631b84f85eb4af10aebd92dec0a870e038fdd9820aae836edba7ba2fae915d6fc25e5727621adc1dffffffff0260011200000000001976a9147c442f8fcb7c525720ee3b587e561fffe028c16d88ac1088810e000000001976a91460b18c23c1d6139e337a306413119f6e9efda4e388ac00000000",
    ];
    let txs: Vec<TransactionWrapper> = txs
        .into_iter()
        .map(|tx| parse_hex_transaction(tx).unwrap())
        .map(Into::into)
        .collect();

    let header = HeaderWrapper::new(
        Header {
            version: Version::from_consensus(536870912),
            prev_blockhash: BlockHash::from_str(
                "6b15a2e4b17b0aabbd418634ae9410b46feaabf693eea4c8621ffe71435d24b0",
            )
            .unwrap(),
            merkle_root: TxMerkleNode::from_slice(&[
                164, 71, 72, 235, 241, 189, 131, 141, 120, 210, 207, 233, 212, 171, 56, 52, 25, 40,
                83, 62, 135, 211, 81, 44, 3, 109, 10, 127, 210, 213, 124, 221,
            ])
            .unwrap(),
            time: 1694177029,
            bits: CompactTarget::from_unprefixed_hex("207fffff").unwrap(),
            nonce: 0,
        },
        6,
        2,
        WitnessMerkleNode::from_str(
            "a8b25755ed6e2f1df665b07e751f6acc1ff4e1ec765caa93084176e34fa5ad71",
        )
        .unwrap()
        .to_raw_hash()
        .to_byte_array(),
    );

    BitcoinBlock {
        header,
        txdata: txs,
    }
}

#[allow(unused)]
pub fn get_mock_false_signature_txs_block() -> BitcoinBlock {
    let txs = [
        "020000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0402aa0800ffffffff026faa040000000000160014fa5554be100ee542587688a93e7c2ac37478bdc60000000000000000266a24aa21a9ed494880ce756f69b13811200d1e358a049ac3c3dd66e4ff7e86d4c4d3aad959390120000000000000000000000000000000000000000000000000000000000000000000000000",
        "020000000001015ada1242404efd013244c1361f3207d3e34a1f0c786a96b334203bcb317dc9e40100000000fdffffff025e0300000000000022512057c195448a1acba9a08b93aa31fc224988f0e1f517908ea814bd4b052dee3df8af31000000000000160014ba033fad8b4899045c892787ff716877e5f8e18102473044022066e4bafa74ad683ecee03d2a9502ed5bda1c2c791efdc91cd82f47f0a7d139e102207a52d868d9e3f2ceeafb0c01c0f6b3e5db43ec41969d5e9740ebb86f8537b0e00121034716b0a10b8e9a64acfa721fccaf7202c5156a2686332b0ec72bbb257d2dbe0600000000",
        "0200000000010171f88e369556505b8c5ca67625daf351d79b9fec757ba9d1259a0b63b2338b3a0000000000fdffffff012202000000000000160014ba033fad8b4899045c892787ff716877e5f8e18103409646f749c4d980a427151c31f9e1129327d4d311caab29bfa7702d674c8aaa1c9fea6547c5c947b9745a5f3ecdeb3235d8b9b0cae6a861df2e43b245c5b16161c72059975a92015d3ca4b95d3b3faffd5003ad389ab064e1144f6a5144e4e6f56a58ad020000006340bd068f826f4ca54e7d2aa7133a0ac9f945ac0e3904ea8ed203b35f430e02d5b07ed2fb9dd6e24f7930a56de2f6772f62d0b453a68ec6a5e58ef6de0094e39d6621035c4edf0c1cc8e9d8eab292be0eee726de6ece392529d5159e75f0fd68609a4b331000d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0dea030000000000004c040000000000006808f9420000000000007721c059975a92015d3ca4b95d3b3faffd5003ad389ab064e1144f6a5144e4e6f56a5800000000",
    ];
    let txs: Vec<TransactionWrapper> = txs
        .into_iter()
        .map(|tx| parse_hex_transaction(tx).unwrap())
        .map(Into::into)
        .collect();

    let header = HeaderWrapper::new(
        Header {
            version: Version::from_consensus(536870912),
            prev_blockhash: BlockHash::from_str(
                "31402555f54c3f89907c07e6d286c132f9984739f2b6b00cde195b10ac771522",
            )
            .unwrap(),
            merkle_root: TxMerkleNode::from_str(
                "40642938a6cc6124246fd9601108f9671177c1834753162f19e073eaff751191",
            )
            .unwrap(),
            time: 1724665818,
            bits: CompactTarget::from_unprefixed_hex("207fffff").unwrap(),
            nonce: 3,
        },
        3,
        1,
        WitnessMerkleNode::from_str(
            "494880ce756f69b13811200d1e358a049ac3c3dd66e4ff7e86d4c4d3aad95939",
        )
        .unwrap()
        .as_raw_hash()
        .to_byte_array(),
    );

    BitcoinBlock {
        header,
        txdata: txs,
    }
}

/// Creates and funds a wallet. Funds are not finalized until `finalize_funds` is called.
async fn create_and_fund_wallet(wallet: String, da_node: &BitcoinNode) {
    da_node
        .client()
        .create_wallet(&wallet, None, None, None, None)
        .await
        .unwrap();

    da_node.fund_wallet(wallet, 5).await.unwrap();
}

/// Generates 100 blocks and finalizes funds
async fn finalize_funds(da_node: &BitcoinNode) {
    da_node.generate(100).await.unwrap();
}

pub fn get_citrea_path() -> PathBuf {
    std::env::var("CITREA_E2E_TEST_BINARY").map_or_else(
        |_| {
            get_workspace_root()
                .join("target")
                .join("debug")
                .join("citrea")
        },
        PathBuf::from,
    )
}

fn get_tx_backup_dir() -> String {
    get_workspace_root()
        .join("resources")
        .join("bitcoin")
        .join("inscription_txs")
        .to_str()
        .unwrap()
        .to_string()
}

fn get_workspace_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(2)
        .expect("Failed to find workspace root")
        .to_path_buf()
}

#[allow(unused)]
pub enum MockData {
    ToBatchProver,
    ToLightClient,
}

#[allow(unused)]
pub fn get_blob_with_sender(tx: &Transaction, ty: MockData) -> anyhow::Result<BlobWithSender> {
    let (blob, public_key, hash) = match ty {
        MockData::ToBatchProver => {
            let parsed_tx = parse_batch_proof_transaction(tx)?;
            match parsed_tx {
                ParsedBatchProofTransaction::SequencerCommitment(seq_com) => {
                    let hash = seq_com
                        .get_sig_verified_hash()
                        .expect("Invalid sighash on commitment");
                    (seq_com.body, seq_com.public_key, hash)
                }
            }
        }
        MockData::ToLightClient => {
            let parsed_tx = parse_light_client_transaction(tx)?;
            match parsed_tx {
                ParsedLightClientTransaction::Complete(complete) => {
                    let hash = complete
                        .get_sig_verified_hash()
                        .expect("Invalid sighash on complete zk proof");
                    let blob = decompress_blob(&complete.body);
                    (blob, complete.public_key, hash)
                }
                ParsedLightClientTransaction::Aggregate(aggregate) => {
                    let hash = aggregate
                        .get_sig_verified_hash()
                        .expect("Invalid sighash on aggregate zk proof");
                    (aggregate.body, aggregate.public_key, hash)
                }
                _ => unimplemented!(),
            }
        }
    };

    Ok(BlobWithSender::new(blob.clone(), public_key, hash))
}

// For some reason, even though macro is used, it sees it as unused
#[allow(unused)]
pub mod macros {
    macro_rules! assert_panic {
        // Match a single expression
        ($expr:expr) => {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $expr)) {
                Ok(_) => panic!("Expression did not trigger panic"),
                Err(_) => (),
            }
        };
        // Match an expression and an expected message
        ($expr:expr, $expected_msg:expr) => {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $expr)) {
                Ok(_) => panic!("Expression did not trigger panic"),
                Err(err) => {
                    let expected_msg = $expected_msg;
                    if let Some(msg) = err.downcast_ref::<&str>() {
                        assert!(
                            msg.contains(expected_msg),
                            "Panic message '{}' does not match expected '{}'",
                            msg,
                            expected_msg
                        );
                    } else if let Some(msg) = err.downcast_ref::<String>() {
                        assert!(
                            msg.contains(expected_msg),
                            "Panic message '{}' does not match expected '{}'",
                            msg,
                            expected_msg
                        );
                    } else {
                        panic!(
                            "Panic occurred, but message does not match expected '{}'",
                            expected_msg
                        );
                    }
                }
            }
        };
    }

    pub(crate) use assert_panic;
}
