use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use bitcoin::absolute::LockTime;
use bitcoin::block::Header;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness, WitnessMerkleNode,
};
use bitcoin_da::helpers::merkle_tree::BitcoinMerkleTree;
use bitcoin_da::helpers::parsers::parse_hex_transaction;
use bitcoin_da::service::BitcoinService;
use bitcoin_da::spec::block::BitcoinBlock;
use bitcoin_da::spec::header::HeaderWrapper;
use bitcoin_da::spec::proof::InclusionMultiProof;
use bitcoin_da::spec::transaction::TransactionWrapper;
use bitcoin_da::spec::RollupParams;
use bitcoin_da::verifier::{BitcoinVerifier, ValidationError, WITNESS_COMMITMENT_PREFIX};
use citrea_e2e::config::{BitcoinConfig, TestCaseConfig};
use citrea_e2e::framework::TestFramework;
use citrea_e2e::test_case::{TestCase, TestCaseRunner};
use citrea_e2e::Result;
use citrea_primitives::REVEAL_TX_PREFIX;
use reth_tasks::TaskManager;
use sov_rollup_interface::da::{BlobReaderTrait, BlockHeaderTrait, DaVerifier};
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::Network;

use crate::bitcoin::get_citrea_path;
use crate::bitcoin::utils::macros::assert_panic;
use crate::bitcoin::utils::{generate_mock_txs, get_default_service};

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
            version: bitcoin::block::Version::from_consensus(536870912),
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
            "dd7cd5d27f0a6d032c51d3873e5328193438abd4e9cfd2788d83bdf1eb4847a4",
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

struct BitcoinVerifierTest {
    task_manager: TaskManager,
}

#[async_trait]
impl TestCase for BitcoinVerifierTest {
    fn test_config() -> TestCaseConfig {
        // Only run bitcoin regtest
        TestCaseConfig {
            with_sequencer: false,
            ..Default::default()
        }
    }

    fn bitcoin_config() -> BitcoinConfig {
        BitcoinConfig {
            extra_args: vec!["-limitancestorcount=50", "-limitdescendantcount=50"],
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

        let da_node = f.bitcoin_nodes.get(0).unwrap();

        let service = get_default_service(&task_executor, &da_node.config).await;
        let (block, _, _, _) = generate_mock_txs(&service, da_node, &task_executor).await;

        let (mut txs, inclusion_proof, completeness_proof) =
            service.extract_relevant_blobs_with_proof(&block);

        txs.iter_mut().for_each(|t| {
            t.full_data();
        });

        let verifier = BitcoinVerifier::new(RollupParams {
            reveal_tx_prefix: REVEAL_TX_PREFIX.to_vec(),
            network: Network::Nightly,
        });

        // Can be verified
        {
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof.clone(),
                    completeness_proof.clone(),
                ),
                Ok(txs.clone()),
            );
        }

        // Test non-segwit block
        {
            let nonsegwit_block = get_mock_nonsegwit_block();
            let txs = nonsegwit_block.txdata.as_slice();

            let tree = BitcoinMerkleTree::new(
                txs.iter()
                    .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                    .collect(),
            );

            let inclusion_proof = InclusionMultiProof {
                wtxids: txs
                    .iter()
                    .map(|t| t.compute_wtxid().to_raw_hash().to_byte_array())
                    .collect(),
                coinbase_tx: txs[0].clone(),
                coinbase_merkle_proof: tree.get_idx_path(0),
            };
            assert_eq!(
                verifier.verify_transactions(&nonsegwit_block.header, inclusion_proof, vec![],),
                Ok(Vec::new())
            );
        }

        // False coinbase input witness should fail
        {
            let mut block_txs = block.txdata.clone();

            // Malform witness
            block_txs[0].input[0].witness = Witness::from_slice(&[vec![1; 32]]);

            // Recreate inclusion proof
            let tree = BitcoinMerkleTree::new(
                block_txs
                    .iter()
                    .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                    .collect(),
            );
            let mut inclusion_proof = InclusionMultiProof {
                wtxids: block_txs
                    .iter()
                    .map(|t| t.compute_wtxid().to_byte_array())
                    .collect(),
                coinbase_tx: block_txs[0].clone(),
                coinbase_merkle_proof: tree.get_idx_path(0),
            };
            // Coinbase tx wtxid should be [0u8;32]
            inclusion_proof.wtxids[0] = [0; 32];

            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof,
                    completeness_proof.clone(),
                ),
                Err(ValidationError::IncorrectWitnessCommitment),
            );
        }

        // False coinbase script pubkey should fail
        {
            let mut block_txs = block.txdata.clone();

            let idx = block_txs[0]
                .output
                .iter()
                .position(|output| {
                    output
                        .script_pubkey
                        .to_bytes()
                        .starts_with(WITNESS_COMMITMENT_PREFIX)
                })
                .unwrap();
            // Malform coinbase script pubkey
            let mut bytes = block_txs[0].output[idx].script_pubkey.to_bytes();
            bytes[6] = bytes[6].wrapping_add(1);

            block_txs[0].output[idx].script_pubkey = ScriptBuf::from_bytes(bytes);

            // Recreate inclusion proof
            let tree = BitcoinMerkleTree::new(
                block_txs
                    .iter()
                    .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                    .collect(),
            );
            let mut inclusion_proof = InclusionMultiProof {
                wtxids: block_txs
                    .iter()
                    .map(|t| t.compute_wtxid().to_byte_array())
                    .collect(),
                coinbase_tx: block_txs[0].clone(),
                coinbase_merkle_proof: tree.get_idx_path(0),
            };
            // Coinbase tx wtxid should be [0u8;32]
            inclusion_proof.wtxids[0] = [0; 32];

            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof,
                    completeness_proof.clone(),
                ),
                Err(ValidationError::IncorrectWitnessCommitment),
            );
        }

        // False witness script should fail
        {
            let mut block_txs = block.txdata.clone();
            let mut completeness_proof = completeness_proof.clone();

            let relevant_tx = block_txs
                .iter_mut()
                .find(|tx| tx.compute_wtxid() == completeness_proof[0].compute_wtxid())
                .unwrap();

            // Malform the witness
            let mut malformed_witness = relevant_tx.input[0].witness.to_vec();
            malformed_witness[0][0] = malformed_witness[0][0].wrapping_add(1);

            completeness_proof[0].input[0].witness = Witness::from_slice(&malformed_witness);
            relevant_tx.input[0].witness = Witness::from_slice(&malformed_witness);
            assert_eq!(
                completeness_proof[0].compute_wtxid(),
                relevant_tx.compute_wtxid()
            );

            let tree = BitcoinMerkleTree::new(
                block_txs
                    .iter()
                    .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                    .collect(),
            );

            let inclusion_proof = InclusionMultiProof {
                wtxids: block_txs
                    .iter()
                    .map(|t| t.compute_wtxid().to_byte_array())
                    .collect(),
                coinbase_tx: block_txs[0].clone(),
                coinbase_merkle_proof: tree.get_idx_path(0),
            };

            assert_eq!(
                verifier.verify_transactions(&block.header, inclusion_proof, completeness_proof,),
                Err(ValidationError::RelevantTxNotInProof),
            );
        }

        // Different witness ids should fail
        {
            let mut ip = inclusion_proof.clone();

            // Prefix is made 2, which will look like inclusion proof
            // has extra relevant transaction in it.
            ip.wtxids[0] = [2; 32];
            assert_eq!(
                verifier.verify_transactions(&block.header, ip, completeness_proof.clone(),),
                Err(ValidationError::RelevantTxNotInProof),
            );

            let mut ip = inclusion_proof.clone();

            ip.wtxids[1] = [16; 32];
            assert_eq!(
                verifier.verify_transactions(&block.header, ip, completeness_proof.clone(),),
                Err(ValidationError::IncorrectWitnessCommitment),
            );
        }

        // Extra tx in inclusion
        {
            let mut inclusion_proof = inclusion_proof.clone();

            inclusion_proof.wtxids.push([5; 32]);
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof,
                    completeness_proof.clone(),
                ),
                Err(ValidationError::HeaderInclusionTxCountMismatch),
            );
        }

        // Missing tx in inclusion should fail
        {
            let mut inclusion_proof = inclusion_proof.clone();

            inclusion_proof.wtxids.pop();
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof,
                    completeness_proof.clone(),
                ),
                Err(ValidationError::HeaderInclusionTxCountMismatch),
            );
        }

        // Break order of inclusion should fail
        {
            let mut inclusion_proof = inclusion_proof.clone();

            inclusion_proof.wtxids.swap(0, 1);
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof,
                    completeness_proof.clone(),
                ),
                Err(ValidationError::IncorrectWitnessCommitment),
            );
        }

        // Missing tx in completeness proof should panic
        {
            let mut completeness_proof = completeness_proof.clone();

            completeness_proof.pop();
            assert_panic!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof.clone(),
                    completeness_proof,
                ),
                "itertools: .zip_eq() reached end of one iterator before the other"
            );
        }

        // Extra tx in completeness proof should panic
        {
            let mut completeness_proof = completeness_proof.clone();

            completeness_proof.push(block.txdata[0].clone());
            assert_panic!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof.clone(),
                    completeness_proof,
                ),
                "itertools: .zip_eq() reached end of one iterator before the other"
            );
        }

        // Nonrelevant tx in completeness proof should fail
        {
            let mut completeness_proof = completeness_proof.clone();

            let nonrelevant_tx = block
                .txdata
                .iter()
                .find(|tx| !completeness_proof.contains(tx))
                .unwrap()
                .clone();
            completeness_proof[0] = nonrelevant_tx;
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof.clone(),
                    completeness_proof,
                ),
                Err(ValidationError::RelevantTxNotInProof),
            );
        }

        // Break completeness proof order should fail
        {
            let mut completeness_proof = completeness_proof.clone();

            completeness_proof.swap(1, 2);
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof.clone(),
                    completeness_proof,
                ),
                Err(ValidationError::RelevantTxNotInProof),
            );
        }

        // Break tx order and completeness proof order should fail
        {
            let mut completeness_proof = completeness_proof.clone();
            let mut txs = txs.clone();

            completeness_proof.swap(0, 1);
            txs.swap(0, 1);
            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof.clone(),
                    completeness_proof,
                ),
                Err(ValidationError::RelevantTxNotInProof),
            );
        }

        // Tamper coinbase merkle proof
        {
            let mut inclusion_proof = inclusion_proof.clone();
            inclusion_proof.coinbase_merkle_proof[0] = [0; 32];

            assert_eq!(
                verifier.verify_transactions(
                    &block.header,
                    inclusion_proof,
                    completeness_proof.clone(),
                ),
                Err(ValidationError::IncorrectTxidCommitment),
            );
        }

        // Tx count set to 1 but txs_commitment is not [0; 32]
        {
            let header = HeaderWrapper::new(*block.header.inner(), 1, 1, [1; 32]);

            // Keep only the coinbase transaction in the inclusion proof
            let mut modified_inclusion = inclusion_proof.clone();
            modified_inclusion.wtxids = vec![inclusion_proof.wtxids[0]];

            assert_eq!(
                verifier.verify_transactions(&header, modified_inclusion, vec![],),
                Err(ValidationError::InvalidSegWitCommitment),
            );
        }

        // Tx count higher than 1 in a non segwit block but header merkle root doesn't match txs_commitment
        {
            let nonsegwit_block = get_mock_nonsegwit_block();
            let header = HeaderWrapper::new(
                *block.header.inner(),
                nonsegwit_block.txdata.len() as u32,
                1,
                [1; 32],
            );
            let (_, inclusion_proof, _) =
                service.extract_relevant_blobs_with_proof(&nonsegwit_block);

            assert_eq!(
                verifier.verify_transactions(&header, inclusion_proof, vec![]),
                Err(ValidationError::InvalidSegWitCommitment),
            );
        }

        // merkle_root is not equal to header txs commitment
        {
            // Set a txs_commitment different from the wtxid merkle root
            let modified_header = HeaderWrapper::new(
                *block.header.inner(),
                inclusion_proof.wtxids.len() as u32,
                1,
                [1; 32],
            );

            assert_eq!(
                verifier.verify_transactions(
                    &modified_header,
                    inclusion_proof.clone(),
                    completeness_proof.clone(),
                ),
                Err(ValidationError::InvalidSegWitCommitment),
            );
        }

        self.test_malicious_witness_prefix_only(&verifier)?;

        self.test_malicious_witness_empty_witness(&verifier)?;

        self.test_malicious_multiple_witness_commitments(&verifier, &service, &block)
            .await?;

        Ok(())
    }
}

impl BitcoinVerifierTest {
    // Test protection against malicious blocks with truncated witness commitment outputs.
    // Bitcoin core protocol does witness malleation check only if it matches MINIMUM_WITNESS_COMMITMENT_SIZE
    // This witness commitment structure would be ignored from bitcoin core verification logic and is a valid block that needs to be
    // handled on our side. An additional MINIMUM_WITNESS_COMMITMENT_SIZE check is added to find the commitment index.
    // In that case, no commmitment index is found and this block is treated as one without relevant txs
    fn test_malicious_witness_prefix_only(&self, verifier: &BitcoinVerifier) -> Result<()> {
        let coinbase_input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: Builder::new().push_int(1).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let reward_output = TxOut {
            value: Amount::from_sat(5000000000),
            script_pubkey: ScriptBuf::from_hex("76a914").unwrap(),
        };

        // Create a malicious witness commitment output with only the prefix.
        // This should fail to pass the MINIMUM_WITNESS_COMMITMENT_SIZE check and be ignored
        let malicious_witness_commitment = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(WITNESS_COMMITMENT_PREFIX.to_vec()),
        };

        let malicious_coinbase = TransactionWrapper::from(Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![coinbase_input],
            output: vec![reward_output, malicious_witness_commitment],
        });

        let malicious_txs = [malicious_coinbase.clone()];

        let tree = BitcoinMerkleTree::new(
            malicious_txs
                .iter()
                .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                .collect(),
        );

        let inclusion_proof = InclusionMultiProof {
            wtxids: malicious_txs
                .iter()
                .map(|t| t.compute_wtxid().to_raw_hash().to_byte_array())
                .collect(),
            coinbase_tx: malicious_coinbase,
            coinbase_merkle_proof: tree.get_idx_path(0),
        };

        let header = Header {
            version: bitcoin::block::Version::from_consensus(0x20000000),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::from_byte_array(tree.root()),
            time: 1,
            bits: CompactTarget::from_consensus(1),
            nonce: 0,
        };

        let malicious_header = HeaderWrapper::new(header, 1, 1, [0; 32]);

        // This malicious block should be ignored
        assert_eq!(
            verifier.verify_transactions(&malicious_header, inclusion_proof, vec![],),
            Ok(Vec::new())
        );
        Ok(())
    }

    // Test protection against malicious blocks with witness commitments but invalid witness structure.
    // This wouldn't pass bitcoin core protocol validation but verifies the `InvalidWitnessCommitmentStructure` safeguard
    fn test_malicious_witness_empty_witness(&self, verifier: &BitcoinVerifier) -> Result<()> {
        let coinbase_input = TxIn {
            previous_output: OutPoint::null(),
            script_sig: Builder::new().push_int(1).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(), // Empty witness
        };

        let reward_output = TxOut {
            value: Amount::from_sat(5000000000),
            script_pubkey: ScriptBuf::from_hex("76a914").unwrap(),
        };

        let witness_commitment = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(
                [WITNESS_COMMITMENT_PREFIX.to_vec(), vec![0u8; 32]].concat(),
            ),
        };

        let malicious_coinbase = TransactionWrapper::from(Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![coinbase_input],
            output: vec![reward_output, witness_commitment],
        });

        let malicious_txs = [malicious_coinbase.clone()];

        let tree = BitcoinMerkleTree::new(
            malicious_txs
                .iter()
                .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                .collect(),
        );

        let inclusion_proof = InclusionMultiProof {
            wtxids: malicious_txs
                .iter()
                .map(|t| t.compute_wtxid().to_raw_hash().to_byte_array())
                .collect(),
            coinbase_tx: malicious_coinbase,
            coinbase_merkle_proof: tree.get_idx_path(0),
        };

        let header = Header {
            version: bitcoin::block::Version::from_consensus(0x20000000),
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::from_byte_array(tree.root()),
            time: 1,
            bits: CompactTarget::from_consensus(1),
            nonce: 0,
        };
        let malicious_header = HeaderWrapper::new(header, 1, 1, [0; 32]);

        // This malicious block should be caught has having an invalid witness commitment structure
        assert_eq!(
            verifier.verify_transactions(&malicious_header, inclusion_proof, vec![],),
            Err(ValidationError::InvalidWitnessCommitmentStructure)
        );

        Ok(())
    }

    /// Test protection against malicious blocks with multiple witness commitment outputs.
    ///
    /// This test verifies that the verifier correctly handles coinbase transactions that
    /// contain multiple outputs with witness commitment prefixes, where some may be
    /// malformed or malicious. In line with BIP-141 [https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki], only the commitment with the highest
    /// output index should be considered valid, and malformed commitments should be ignored.
    async fn test_malicious_multiple_witness_commitments(
        &self,
        verifier: &BitcoinVerifier,
        service: &BitcoinService,
        block: &BitcoinBlock,
    ) -> Result<()> {
        let (mut original_txs, original_inclusion_proof, original_completeness_proof) =
            service.extract_relevant_blobs_with_proof(block);
        original_txs.iter_mut().for_each(|t| {
            t.full_data();
        });

        let original_coinbase = &block.txdata[0];

        let malformed_witness_commitment = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(WITNESS_COMMITMENT_PREFIX.to_vec()),
        };

        let invalid_witness_commitment = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(
                [WITNESS_COMMITMENT_PREFIX.to_vec(), vec![1u8; 32]].concat(),
            ),
        };

        // Create new coinbase with malicious witness commitments
        let mut new_outputs = original_coinbase.output.clone();

        // Insert malicious commitments before the original valid one
        new_outputs.insert(1, malformed_witness_commitment);
        new_outputs.insert(2, invalid_witness_commitment);

        let malicious_coinbase = TransactionWrapper::from(Transaction {
            version: original_coinbase.version,
            lock_time: original_coinbase.lock_time,
            input: original_coinbase.input.clone(),
            output: new_outputs,
        });

        let mut malicious_txs = block.txdata.clone();
        malicious_txs[0] = malicious_coinbase.clone();

        let tree = BitcoinMerkleTree::new(
            malicious_txs
                .iter()
                .map(|t| t.compute_txid().to_raw_hash().to_byte_array())
                .collect(),
        );

        // Create new inclusion proof with the malicious coinbase
        let malicious_inclusion_proof = InclusionMultiProof {
            wtxids: original_inclusion_proof.wtxids.clone(),
            coinbase_tx: malicious_coinbase,
            coinbase_merkle_proof: tree.get_idx_path(0),
        };

        // Update the block header with new merkle root
        let mut new_header = *block.header.inner();
        new_header.merkle_root = bitcoin::TxMerkleNode::from_byte_array(tree.root());

        let malicious_header = HeaderWrapper::new(
            new_header,
            block.header.tx_count(),
            block.header.height(),
            block.header.txs_commitment().to_byte_array(),
        );

        // The verifier should still successfully extract the relevant txs
        // and ignore the malicious additional witness commitments
        let result = verifier.verify_transactions(
            &malicious_header,
            malicious_inclusion_proof,
            original_completeness_proof,
        );

        assert_eq!(result, Ok(original_txs));

        Ok(())
    }
}

#[tokio::test]
async fn test_bitcoin_verifier() -> Result<()> {
    TestCaseRunner::new(BitcoinVerifierTest {
        task_manager: TaskManager::current(),
    })
    .set_citrea_path(get_citrea_path())
    .run()
    .await
}
