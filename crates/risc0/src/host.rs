//! This module implements the [`ZkvmHost`] trait for the RISC0 VM.

use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{
    compute_image_id, default_prover, AssumptionReceipt, ExecutorEnvBuilder, ProveInfo, ProverOpts,
    Receipt,
};
use sov_db::ledger_db::LedgerDB;
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};
use tracing::{debug, info};

use crate::guest::Risc0Guest;

type StarkSessionId = String;
type SnarkSessionId = String;

/// Bonsai sessions to be recovered in case of a crash.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum BonsaiSession {
    /// Stark session id if the prover crashed during stark proof generation.
    StarkSession(StarkSessionId),
    /// Both Stark and Snark session id if the prover crashed during stark to snarkconversion.
    SnarkSession(StarkSessionId, SnarkSessionId),
}

/// Recovered bonsai session.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RecoveredBonsaiSession {
    /// Used for sending proofs in order
    pub id: u8,
    /// Recovered session
    pub session: BonsaiSession,
}

/// A [`Risc0BonsaiHost`] stores a binary to execute in the Risc0 VM and prove in the Risc0 Bonsai API.
#[derive(Clone)]
pub struct Risc0BonsaiHost {
    env: Vec<u8>,
    assumptions: Vec<AssumptionReceipt>,
    _ledger_db: LedgerDB,
}

impl Risc0BonsaiHost {
    /// Create a new Risc0Host to prove the given binary.
    pub fn new(ledger_db: LedgerDB) -> Self {
        match std::env::var("RISC0_PROVER") {
            Ok(prover) => match prover.as_str() {
                "bonsai" => {
                    if std::env::var("BONSAI_API_URL").is_err()
                        || std::env::var("BONSAI_API_KEY").is_err()
                    {
                        panic!("Bonsai API URL and API key must be set when RISC0_PROVER is set to bonsai");
                    }
                }
                "local" => {}
                "ipc" => {
                    if std::env::var("RISC0_SERVER_PATH").is_err() {
                        panic!("RISC0_SERVER_PATH must be set when RISC0_PROVER is set to ipc");
                    }
                }
                _ => {
                    panic!("Invalid prover specified: {}", prover);
                }
            },
            Err(_) => {
                debug!("No prover specified.");

                if std::env::var("BONSAI_API_URL").is_ok()
                    && std::env::var("BONSAI_API_KEY").is_ok()
                {
                    panic!(
                        "Bonsai API URL and API key are set, but RISC0_PROVER is not set to bonsai"
                    );
                }
            }
        }

        Self {
            env: Default::default(),
            assumptions: vec![],
            _ledger_db: ledger_db,
        }
    }
}

impl ZkvmHost for Risc0BonsaiHost {
    type Guest = Risc0Guest;

    fn add_hint(&mut self, item: Vec<u8>) {
        info!("Added hint to guest with size {}", item.len());

        // write buf
        self.env.extend_from_slice(&item);
    }

    /// Guest simulation (execute mode) is run inside the Risc0 VM locally
    fn simulate_with_hints(&mut self) -> Self::Guest {
        todo!("we don't use it yet")
    }

    fn add_assumption(&mut self, receipt_buf: Vec<u8>) {
        let receipt: Receipt = bincode::deserialize(&receipt_buf).expect("Receipt should be valid");
        self.assumptions.push(receipt.into());
    }

    /// Only with_proof = true is supported.
    /// Proofs are created on the Bonsai API.
    fn run(&mut self, elf: Vec<u8>, with_proof: bool) -> Result<Proof, anyhow::Error> {
        if !with_proof {
            if std::env::var("RISC0_PROVER") == Ok("bonsai".to_string()) {
                panic!("Bonsai prover requires with_proof to be true");
            }

            std::env::set_var("RISC0_DEV_MODE", "1");
        }

        let mut env = ExecutorEnvBuilder::default();
        for assumption in self.assumptions.iter() {
            env.add_assumption(assumption.clone());
        }

        tracing::debug!("{:?} assumptions added to the env", self.assumptions.len());

        let env = env.write_slice(&self.env).build().unwrap();

        // The `RISC0_PROVER` environment variable, if specified, will select the
        // following [Prover] implementation:
        // * `bonsai`: [BonsaiProver] to prove on Bonsai.
        // * `local`: LocalProver to prove locally in-process. Note: this
        //   requires the `prove` feature flag.
        // * `ipc`: [ExternalProver] to prove using an `r0vm` sub-process. Note: `r0vm`
        //   must be installed. To specify the path to `r0vm`, use `RISC0_SERVER_PATH`.
        let prover = default_prover();

        tracing::info!("Starting risc0 proving");
        let ProveInfo { receipt, stats } =
            prover.prove_with_opts(env, &elf, &ProverOpts::groth16())?;

        tracing::info!("Execution Stats: {:?}", stats);

        let image_id = compute_image_id(&elf)?;

        receipt.verify(image_id)?;
        tracing::trace!("Calculated image id: {:?}", image_id.as_words());

        tracing::info!("Verified the receipt");

        let serialized_receipt = bincode::serialize(&receipt)?;

        // Cleanup env
        self.env.clear();

        // Cleanup assumptions
        self.assumptions.clear();

        Ok(serialized_receipt)
    }

    fn extract_output<Da: sov_rollup_interface::da::DaSpec, T: BorshDeserialize>(
        proof: &Proof,
    ) -> Result<T, Self::Error> {
        let receipt: Receipt = bincode::deserialize(proof)?;
        let journal = receipt.journal;

        Ok(T::try_from_slice(&journal.bytes)?)
    }

    fn recover_proving_sessions(&self) -> Result<Vec<Proof>, anyhow::Error> {
        Ok(Vec::new())

        // TODO: fix this https://github.com/chainwayxyz/citrea/issues/1410
        //
        // let sessions = self.ledger_db.get_pending_proving_sessions()?;
        // tracing::info!("Recovering {} bonsai sessions", sessions.len());
        // let mut proofs = Vec::new();
        // for session in sessions {
        //     let bonsai_session: RecoveredBonsaiSession = BorshDeserialize::try_from_slice(&session)
        //         .expect("Bonsai host should be able to recover bonsai sessions");

        //     tracing::info!("Recovering bonsai session: {:?}", bonsai_session);
        // match bonsai_session.session {
        //     BonsaiSession::StarkSession(stark_session) => {
        //         let _receipt = self.wait_for_receipt(&stark_session)?;
        //         let proof = self.wait_for_stark_to_snark_conversion(None, &stark_session)?;
        //         proofs.push(proof);
        //     }
        //     BonsaiSession::SnarkSession(stark_session, snark_session) => {
        //         let _receipt = self.wait_for_receipt(&stark_session)?;
        //         let proof = self
        //             .wait_for_stark_to_snark_conversion(Some(&snark_session), &stark_session)?;
        //         proofs.push(proof)
        //     }
        // }
        // }
        // Ok(proofs)
    }
}

impl Zkvm for Risc0BonsaiHost {
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

    fn extract_raw_output(serialized_proof: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let receipt: Receipt = bincode::deserialize(serialized_proof)?;
        Ok(receipt.journal.bytes)
    }

    fn verify_and_extract_output<T: BorshDeserialize>(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<T, Self::Error> {
        let receipt: Receipt = bincode::deserialize(serialized_proof)?;

        #[allow(clippy::clone_on_copy)]
        receipt.verify(code_commitment.clone())?;

        Ok(T::deserialize(&mut receipt.journal.bytes.as_slice())?)
    }
}
