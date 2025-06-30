use bitcoin::hashes::Hash;
use bitcoin::script;
use sov_rollup_interface::da::{
    BlockHeaderTrait, L1UpdateSystemTransactionInfo, ShortHeaderProofVerificationError,
    VerifiableShortHeaderProof,
};

use super::header::HeaderWrapper;
use super::transaction::TransactionWrapper;
use crate::helpers::{calculate_double_sha256, calculate_txid, merkle_tree};
use crate::verifier::WITNESS_COMMITMENT_PREFIX;

#[derive(borsh::BorshDeserialize, borsh::BorshSerialize, Eq, PartialEq, Debug, Clone)]
pub struct BitcoinHeaderShortProof {
    pub(crate) header: HeaderWrapper,
    pub(crate) coinbase_tx: TransactionWrapper,
    pub(crate) coinbase_tx_txid_merkle_proof: Vec<[u8; 32]>,
}

impl BitcoinHeaderShortProof {
    pub fn new(
        header: HeaderWrapper,
        coinbase_tx: TransactionWrapper,
        coinbase_tx_txid_merkle_proof: Vec<[u8; 32]>,
    ) -> Self {
        Self {
            header,
            coinbase_tx,
            coinbase_tx_txid_merkle_proof,
        }
    }
}

impl VerifiableShortHeaderProof for BitcoinHeaderShortProof {
    fn verify(&self) -> Result<L1UpdateSystemTransactionInfo, ShortHeaderProofVerificationError> {
        // First verify that the precomputed (from circuit input) hash actually matches
        // the hash of the header
        if !self.header.verify_hash() {
            return Err(ShortHeaderProofVerificationError::InvalidHeaderHash);
        }

        // Then check inclusion of coinbase tx to the header
        // by calculating txid of coinbase tx
        // and comparing self.header.header.merkle_root with reached merkle root
        // with the given merkle proof
        let claimed_root = merkle_tree::BitcoinMerkleTree::calculate_root_with_merkle_proof(
            calculate_txid(&self.coinbase_tx),
            0,
            &self.coinbase_tx_txid_merkle_proof,
        );

        if self.header.merkle_root() != claimed_root {
            return Err(ShortHeaderProofVerificationError::InvalidCoinbaseMerkleProof);
        }

        // If block has only coinbase tx claimed tx commitment should equal to [0u8; 32]
        if self.header.tx_count == 1 && self.header.txs_commitment != [0u8; 32] {
            return Err(ShortHeaderProofVerificationError::WrongTxCommitment {
                expected: [0u8; 32],
                actual: self.header.txs_commitment,
            });
        }

        // Then extract the wtxid root from the coinbase tx
        // and compare with self.header.txs_comitment()
        let commitment_idx = self.coinbase_tx.output.iter().rev().position(|output| {
            output
                .script_pubkey
                .as_bytes()
                .starts_with(WITNESS_COMMITMENT_PREFIX)
        });

        match commitment_idx {
            None => {
                // If non-segwit block, claimed tx commitment should equal to
                // header.merkle_root if there are more than one tx
                if self.header.tx_count > 1
                    && self.header.merkle_root()
                        != Into::<[u8; 32]>::into(self.header.txs_commitment())
                {
                    return Err(ShortHeaderProofVerificationError::WrongTxCommitment {
                        expected: self.header.merkle_root(),
                        actual: Into::<[u8; 32]>::into(self.header.txs_commitment()),
                    });
                }
            }
            Some(idx) => {
                // If post-segwit block, extract the commitment from the coinbase tx
                // and compare with header.txs_commitment().
                let idx = self.coinbase_tx.output.len() - idx - 1; // The index is reversed
                let script_pubkey = self.coinbase_tx.output[idx].script_pubkey.as_bytes();
                let input_witness_value = self.coinbase_tx.input[0].witness.iter().next().unwrap();

                let mut vec_merkle = Vec::with_capacity(input_witness_value.len() + 32);

                vec_merkle.extend_from_slice(&self.header.txs_commitment().to_byte_array());
                vec_merkle.extend_from_slice(input_witness_value);

                // check with sha256(sha256(<merkle root><witness value>))
                let commitment = calculate_double_sha256(&vec_merkle);

                if script_pubkey[6..38] != commitment {
                    return Err(ShortHeaderProofVerificationError::WrongTxCommitment {
                        expected: script_pubkey[6..38]
                            .try_into()
                            .expect("Must have hash in witness commitment output"),
                        actual: Into::<[u8; 32]>::into(self.header.txs_commitment()),
                    });
                }
            }
        }

        // code taken from
        // bitcoin::Block::bip34_block_height()
        // and slightly modified
        //
        // we use .expect() on these lines as we don't expect
        // non-bip34 blocks on mainnet and testnet
        let input = self
            .coinbase_tx
            .input
            .first()
            .expect("coinbase tx must have input");

        let push = input
            .script_sig
            .instructions_minimal()
            .next()
            .expect("should have at least one instruction")
            .expect("should be minimal");

        let script::Instruction::PushBytes(b) = push else {
            panic!("should be push bytes");
        };

        let height = script::read_scriptint(b.as_bytes()).expect("should work");

        assert!(height > 0, "height must be positive");

        let height = height as u64;

        // Finally return hash, wtxid root, txid proof count, and height
        Ok(L1UpdateSystemTransactionInfo {
            header_hash: self.header.hash().into(),
            prev_header_hash: self
                .header
                .inner()
                .prev_blockhash
                .as_raw_hash()
                .to_byte_array(),
            tx_commitment: self.header.txs_commitment().into(),
            coinbase_txid_merkle_proof_height: self.coinbase_tx_txid_merkle_proof.len() as u8,
            block_height: height,
        })
    }
}

#[cfg(test)]
mod test {
    use std::fs;
    use std::ops::Deref;

    use bitcoin::hashes::Hash;
    use bitcoin::BlockHash;
    use hex::FromHex;
    use sov_rollup_interface::da::{ShortHeaderProofVerificationError, VerifiableShortHeaderProof};
    use sov_rollup_interface::services::da::DaService;

    use super::BitcoinHeaderShortProof;
    use crate::helpers::parsers::parse_hex_transaction;
    use crate::service::BitcoinService;
    use crate::spec::block::BitcoinBlock;
    use crate::spec::block_hash::BlockHashWrapper;
    use crate::spec::header::HeaderWrapper;

    fn get_proof() -> BitcoinHeaderShortProof {
        let block = fs::read("test_data/mainnet/block-882547.bin").unwrap();

        let block: bitcoin::Block = bitcoin::consensus::deserialize(block.as_slice()).unwrap();

        let block = BitcoinBlock {
            header: HeaderWrapper::new(
                block.header,
                block.txdata.len() as u32,
                882547,
                <[u8; 32]>::from_hex(
                    // Witness root
                    "9d652dffd72f7201dd0dbb598f864561a31183d10b9258bd4b35589ec3b0e91b",
                )
                .unwrap(),
            ),
            txdata: block.txdata.into_iter().map(Into::into).collect(),
        };

        BitcoinService::block_to_short_header_proof(block)
    }

    #[test]
    fn test_correct_short_proof() {
        let proof = get_proof();

        let l1_update = proof.verify().expect("Proof verification failed");

        let mut hash_from_input = <[u8; 32]>::from_hex(
            "00000000000000000001a33628ffb58f0705f17815b9b789fe23ad64bfbbeb45",
        )
        .unwrap();
        hash_from_input.reverse();
        assert_eq!(l1_update.header_hash, hash_from_input);

        let mut prev_hash_from_input = <[u8; 32]>::from_hex(
            "0000000000000000000274671d48c3af6e9eb2cf9fb5f9128edabac6062a889a",
        )
        .unwrap();
        prev_hash_from_input.reverse();
        assert_eq!(l1_update.prev_header_hash, prev_hash_from_input);

        assert_eq!(
            l1_update.tx_commitment,
            <[u8; 32]>::from_hex(
                "9d652dffd72f7201dd0dbb598f864561a31183d10b9258bd4b35589ec3b0e91b"
            )
            .unwrap()
        );
        assert_eq!(l1_update.coinbase_txid_merkle_proof_height, 11);
        assert_eq!(l1_update.block_height, 882547);
    }

    #[test]
    fn test_incorrect_short_proofs() {
        let proof = get_proof();

        // malform the merkle proof
        {
            let mut proof = proof.clone();
            proof.coinbase_tx_txid_merkle_proof[3] = [8; 32];

            assert_eq!(
                proof.verify().unwrap_err(),
                ShortHeaderProofVerificationError::InvalidCoinbaseMerkleProof
            );
        }

        // put a different coinbase tx to the proof
        {
            let mut proof = proof.clone();
            proof.coinbase_tx = parse_hex_transaction("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff640374770d2cfabe6d6d7534b66e1756195a543deea74059ce5ecc0ccae15a07faf980a62039cd4ef0ed10000000f09f909f092f4632506f6f6c2f640000000000000000000000000000000000000000000000000000000000000000000000050013172f24000000000722020000000000001976a914c6740a12d0a7d556f89782bf5faf0e12cf25a63988acc7b1c412000000001976a914c85526a428126c00ad071b56341a5a553a5e96a388ac0000000000000000266a24aa21a9ed7d0f77a6a13e7308be6b923d7f6f4b9251f7c47a3d383b8698f3f417e947ed0500000000000000002f6a2d434f52450142fdeae88682a965939fee9b7b2bd5b99694ff64e7ec323813c943336c579e238228a8ebd096a7e50000000000000000126a10455853415401051b0f0e0e0b1f1200130000000000000000266a24486174686e30ea617a55d932e1a85798907987dd308b5ccc6bb92e23587f0e9acba77e8800000000000000002c6a4c2952534b424c4f434b3ae3cf1c4319b02fd3b18d21cf129590786c12e5faf3f481c5e6aac512006e119f0120000000000000000000000000000000000000000000000000000000000000000075609341").unwrap().into();

            assert_eq!(
                proof.verify().unwrap_err(),
                ShortHeaderProofVerificationError::InvalidCoinbaseMerkleProof
            );
        }

        // try to change the wtxid merkle root
        {
            let mut proof = proof.clone();
            let mut tx = proof.coinbase_tx.deref().clone();
            // originally df
            tx.output[2].script_pubkey.as_mut_bytes()[37] = 0x00;

            proof.coinbase_tx = tx.into();

            assert_eq!(
                proof.verify().unwrap_err(),
                ShortHeaderProofVerificationError::InvalidCoinbaseMerkleProof,
            );
        }

        // try to supply wrong wtxid
        {
            let mut proof = proof.clone();
            proof.header.txs_commitment = <[u8; 32]>::from_hex(
                "a4d7206595b921ee04f46e76fda0175dea5ad8d227af75110490d05b6a90009c",
            )
            .unwrap();

            assert_eq!(
                proof.verify().unwrap_err(),
                ShortHeaderProofVerificationError::WrongTxCommitment {
                    expected: <[u8; 32]>::from_hex(
                        "a4d7206595b921ee04f46e76fda0175dea5ad8d227af75110490d05b6a90df9c"
                    )
                    .unwrap(),
                    actual: <[u8; 32]>::from_hex(
                        "a4d7206595b921ee04f46e76fda0175dea5ad8d227af75110490d05b6a90009c"
                    )
                    .unwrap()
                }
            )
        }

        // try to input wrong `precomputed_hash`
        {
            let mut proof = proof.clone();
            proof.header.precomputed_hash = BlockHashWrapper(BlockHash::from_byte_array([1u8; 32]));

            assert_eq!(
                proof.verify().unwrap_err(),
                ShortHeaderProofVerificationError::InvalidHeaderHash
            )
        }

        // non segwit wrong tx commitment: 1 txs
        {
            // Verify with no segwit and only coinbase always expects tx commitment to be [0; 32]

            // One-Transaction Non-SegWit Block
            // First TX: Coinbase Transaction
            let block = hex::decode("030000008f6bf399c264ffb224b370a895774da700aee298ee64c30800000000000000005c759d40b6682c185028ae9b352ab1a7039828881c550cee0476d8077beb7b36c796bd55150815181470b5290101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff64039e9d05e4b883e5bda9e7a59ee4bb99e9b1bcfabe6d6de1f60d022c2ad500bf897d07d85cef56c7e4323f24e89cd19bdfda0e4325ec6a10000000f09f909f4d696e65642062792067756f68756100000000000000000000000000000000000000000000d51e00000100f90295000000001976a914c825a1ecf2a6830c4401620c3a16f1995057c2ab88ac896bb334").unwrap();
            let block: bitcoin::Block = bitcoin::consensus::deserialize(block.as_slice()).unwrap();

            assert_eq!(1, block.txdata.len());

            let block = BitcoinBlock {
                header: HeaderWrapper::new(
                    block.header,
                    block.txdata.len() as u32,
                    368030,
                    [1; 32], // MUST BE [0; 32]
                ),
                txdata: block.txdata.into_iter().map(Into::into).collect(),
            };

            let proof = BitcoinService::block_to_short_header_proof(block);

            assert_eq!(
                proof.verify().unwrap_err(),
                ShortHeaderProofVerificationError::WrongTxCommitment {
                    expected: [0; 32],
                    actual: [1; 32]
                }
            )
        }

        // non segwit wrong tx commitment: 2 txs
        {
            // Verify with no segwit and coinbase and a tx always expects tx commitment to be the merkle root of the block

            // Two-Transaction Non-SegWit Block
            // First TX: Coinbase Transaction
            // Second TX: Fake input, send to random P2PKH address
            let block = hex::decode("03000000855d154359b794c6ba2c5586cf6278eee5bd658faa954200000000000000000035e95b187fb0d5175f681c2a1c499c3c91a0781c91679545a1fcabba2cd7cd801b04bd5515081518aa8afeaf0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff25035b9d05384d2f040f04bd550894251c009a0500000f5b4254434368696e612e636f6d5d20000000000100f90295000000001976a9142c30a6aaac6d96687291475d7d52f4b469f665a688ac0000000001000000018651ed89909def949ee3e05631bb332f339f4c667b0af7e2d94e7940a4568a21000000006a473044022059c947c745d94d1019990f39b2c938c9ce3e79fe9a650cff01589ec3b5ed2c2c02206dcff5e15ae6aa9c7d44308f16963dd5ad1dd3229e923c9de3ae1c14f6f91a02012102163e80de410646145142636833d8a92de4bb5c99e49bd52be5346fb1030628d4ffffffff0250ac6002000000001976a9145ca26d65ee83f441ef98b624763a305d50eb36cf88aca0860100000000001976a914838eb1034b719f9c47ab853aee63d505e4176a8388ac00000000").unwrap();
            let block: bitcoin::Block = bitcoin::consensus::deserialize(block.as_slice()).unwrap();

            assert_eq!(2, block.txdata.len());

            let original_merkle_root = block.header.merkle_root;
            let block = BitcoinBlock {
                header: HeaderWrapper::new(
                    block.header,
                    block.txdata.len() as u32,
                    367963,
                    [0; 32], // MUST BE block.header.merkle_root
                ),
                txdata: block.txdata.into_iter().map(Into::into).collect(),
            };

            let proof = BitcoinService::block_to_short_header_proof(block);

            assert_eq!(
                proof.verify().unwrap_err(),
                ShortHeaderProofVerificationError::WrongTxCommitment {
                    expected: original_merkle_root.to_byte_array(),
                    actual: [0; 32]
                }
            )
        }
    }
}
