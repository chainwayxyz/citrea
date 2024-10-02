//! This module implements the [`ZkvmHost`] trait for the RISC0 VM.

use std::thread;
use std::time::Duration;

use anyhow::anyhow;
use backoff::exponential::ExponentialBackoffBuilder;
use backoff::{retry as retry_backoff, SystemClock};
use bitcoin_da::service::BitcoinService;
use bonsai_sdk::blocking::Client;
use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{
    compute_image_id, ExecutorEnvBuilder, ExecutorImpl, Groth16Receipt, InnerReceipt, Journal,
    Receipt,
};
use sov_db::ledger_db::{LedgerDB, ProvingServiceLedgerOps};
// use sov_risc0_adapter::guest::Risc0Guest;
use sov_rollup_interface::services::da::DaService;
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};
use tracing::{error, info, warn};

/// A [`LightClientHost`] stores a binary to execute in the Risc0 VM and prove in the Risc0.
/// We are going to pass the data directly to the Host instead of having a DaService.
#[derive(Clone)]
pub struct LightClientHost<'a> {
    elf: &'a [u8],
    env: Vec<u8>, // All the data taken from BitcoinService.
}

impl<'a> LightClientHost<'a> {
    /// Create a new Risc0Host to prove the given binary.
    pub fn new(elf: &'a [u8], ledger_db: LedgerDB, da_service: BitcoinService) -> Self {
        // Compute the image_id, then upload the ELF with the image_id as its key.
        // handle error
        let image_id = compute_image_id(elf).unwrap();

        tracing::trace!("Calculated image id: {:?}", image_id.as_words());

        Self {
            elf,
            env: Default::default(),
        }
    }
}

// impl<'a> ZkvmHost for LightClientHost<'a> {
//     type Guest = Risc0Guest;

//     fn add_hint<T: BorshSerialize>(&mut self, item: T) {
//         // For running in "execute" mode.

//         let buf = borsh::to_vec(&item).expect("Risc0 hint serialization is infallible");
//         info!("Added hint to guest with size {}", buf.len());

//         // write buf
//         self.env.extend_from_slice(&buf);
//     }

//     /// Guest simulation (execute mode) is run inside the Risc0 VM locally
//     fn simulate_with_hints(&mut self) -> Self::Guest {
//         Risc0Guest::with_hints(std::mem::take(&mut self.env))
//     }

//     /// Only with_proof = true is supported.
//     /// Proofs are created on the Bonsai API.
//     fn run(&mut self, with_proof: bool) -> Result<Proof, anyhow::Error> {
//         unimplemented!()
//     }

//     fn extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
//         proof: &Proof,
//     ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
//         let journal = match proof {
//             Proof::PublicInput(journal) => {
//                 let journal: Journal = bincode::deserialize(journal)?;
//                 journal
//             }
//             Proof::Full(data) => {
//                 let receipt: Receipt = bincode::deserialize(data)?;
//                 receipt.journal
//             }
//         };
//         Ok(BorshDeserialize::try_from_slice(&journal.bytes)?)
//     }
// }

impl<'host> Zkvm for LightClientHost<'host> {
    type CodeCommitment = Digest;

    type Error = anyhow::Error;

    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<Vec<u8>, Self::Error> {
        let receipt: Receipt = bincode::deserialize(serialized_proof)?;

        #[allow(clippy::clone_on_copy)]
        receipt.verify(code_commitment.clone())?;

        Ok(receipt.journal.bytes)
    }

    fn verify_and_extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let receipt: Receipt = bincode::deserialize(serialized_proof)?;

        #[allow(clippy::clone_on_copy)]
        receipt.verify(code_commitment.clone())?;

        Ok(BorshDeserialize::deserialize(
            &mut receipt.journal.bytes.as_slice(),
        )?)
    }
}
