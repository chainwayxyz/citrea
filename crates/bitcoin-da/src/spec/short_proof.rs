use bitcoin::hashes::Hash;
use bitcoin::script;
use sov_rollup_interface::da::{
    BlockHeaderTrait, L1UpdateSystemTransactionInfo, ShortHeaderProofVerificationError,
    VerifableShortHeaderProof,
};

use super::header::HeaderWrapper;
use super::transaction::TransactionWrapper;
use crate::helpers::{calculate_txid, merkle_tree};
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

impl VerifableShortHeaderProof for BitcoinHeaderShortProof {
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
                // header.merkle_root
                if self.header.merkle_root() != Into::<[u8; 32]>::into(self.header.txs_commitment())
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
                if script_pubkey[6..38] != Into::<[u8; 32]>::into(self.header.txs_commitment()) {
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
    use sov_rollup_interface::da::{ShortHeaderProofVerificationError, VerifableShortHeaderProof};
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
                    "a4d7206595b921ee04f46e76fda0175dea5ad8d227af75110490d05b6a90df9c",
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
                "a4d7206595b921ee04f46e76fda0175dea5ad8d227af75110490d05b6a90df9c"
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
    }
}
