use bitcoin::hashes::Hash;
use sov_rollup_interface::da::{
    BlockHeaderTrait, ShortHeaderProofVerificationError, VerifableShortHeaderProof,
};

use super::header::HeaderWrapper;
use super::transaction::TransactionWrapper;
use crate::helpers::{calculate_txid, merkle_tree};
use crate::verifier::WITNESS_COMMITMENT_PREFIX;

#[derive(borsh::BorshDeserialize, borsh::BorshSerialize, Eq, PartialEq, Debug)]
pub struct BitcoinHeaderShortProof {
    header: HeaderWrapper,
    coinbase_tx: TransactionWrapper,
    coinbase_tx_txid_merkle_proof: Vec<[u8; 32]>,
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
    fn verify(&self) -> Result<([u8; 32], [u8; 32], u8), ShortHeaderProofVerificationError> {
        // First verify that the precomputed (inputted) hash actually matches
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
            Some(mut idx) => {
                // If post-segwit block, extract the commitment from the coinbase tx
                // and compare with header.txs_commitment().
                idx = self.coinbase_tx.output.len() - idx - 1; // The index is reversed
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

        // Finally return hash, wtxid root and txid proof count
        return Ok((
            // block_hash calculates the hash of the header
            self.header.hash().into(),
            self.header.txs_commitment().into(),
            self.coinbase_tx_txid_merkle_proof.len() as u8,
        ));
    }
}

#[cfg(test)]
mod test {
    use std::fs;

    use bitcoin::hashes::Hash;
    use hex::FromHex;
    use sov_rollup_interface::da::VerifableShortHeaderProof;
    use sov_rollup_interface::services::da::DaService;

    use crate::service::BitcoinService;
    use crate::spec::block::BitcoinBlock;
    use crate::spec::header::{BitcoinHeaderWrapper, HeaderWrapper};

    #[test]
    fn test_correct_short_proof() {
        let block = fs::read("test_data/mainnet/block-882547.bin").unwrap();

        let block: bitcoin::Block = bitcoin::consensus::deserialize(block.as_slice()).unwrap();

        let block = BitcoinBlock {
            header: HeaderWrapper::new(
                block.header.into(),
                block.txdata.len() as u32,
                882547,
                <[u8; 32]>::from_hex(
                    "a4d7206595b921ee04f46e76fda0175dea5ad8d227af75110490d05b6a90df9c",
                )
                .unwrap(),
            ),
            txdata: block.txdata.into_iter().map(Into::into).collect(),
        };

        let proof = BitcoinService::block_to_short_header_proof(block);

        let (block_hash, tx_commitment, tx_proof_count) =
            proof.verify().expect("Proof verification failed");

        let mut hash_from_input = <[u8; 32]>::from_hex(
            "00000000000000000001a33628ffb58f0705f17815b9b789fe23ad64bfbbeb45",
        )
        .unwrap();

        hash_from_input.reverse();

        assert_eq!(block_hash, hash_from_input);
        assert_eq!(
            tx_commitment,
            <[u8; 32]>::from_hex(
                "a4d7206595b921ee04f46e76fda0175dea5ad8d227af75110490d05b6a90df9c"
            )
            .unwrap()
        );

        assert_eq!(tx_proof_count, 11);
    }
}
