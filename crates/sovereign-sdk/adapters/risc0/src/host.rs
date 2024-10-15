//! This module implements the [`ZkvmHost`] trait for the RISC0 VM.

use borsh::BorshDeserialize;
use risc0_zkvm::{ExecutorEnvBuilder, ExecutorImpl, InnerReceipt, Journal, Receipt, Session};
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};

use crate::guest::Risc0Guest;
use crate::Risc0MethodId;

/// A [`Risc0Host`] stores a binary to execute in the Risc0 VM, and accumulates hints to be
/// provided to its execution.
#[derive(Clone)]
pub struct Risc0Host<'a> {
    env: Vec<u8>,
    elf: &'a [u8],
}

#[cfg(not(feature = "bench"))]
#[inline(always)]
/// Add benchmarking callbacks to the executor environment.
pub fn add_benchmarking_callbacks(env: ExecutorEnvBuilder<'_>) -> ExecutorEnvBuilder<'_> {
    env
}

#[cfg(feature = "bench")]
/// Add benchmarking callbacks to the executor environment.
pub fn add_benchmarking_callbacks(mut env: ExecutorEnvBuilder<'_>) -> ExecutorEnvBuilder<'_> {
    use sov_zk_cycle_utils::{cycle_count_callback, get_syscall_name, get_syscall_name_cycles};

    use crate::metrics::metrics_callback;

    let metrics_syscall_name = get_syscall_name();
    env.io_callback(metrics_syscall_name, metrics_callback);

    let cycles_syscall_name = get_syscall_name_cycles();
    env.io_callback(cycles_syscall_name, cycle_count_callback);

    env
}

impl<'a> Risc0Host<'a> {
    /// Create a new Risc0Host to prove the given binary.
    pub fn new(elf: &'a [u8]) -> Self {
        Self {
            env: Default::default(),
            elf,
        }
    }

    /// Run a computation in the zkVM without generating a receipt.
    /// This creates the "Session" trace without invoking the heavy cryptographic machinery.
    pub fn run_without_proving(&mut self) -> anyhow::Result<Session> {
        let env = add_benchmarking_callbacks(ExecutorEnvBuilder::default())
            .write_slice(&self.env)
            .build()
            .unwrap();
        let mut executor = ExecutorImpl::from_elf(env, self.elf)?;
        executor.run()
    }
    /// Run a computation in the zkvm and generate a receipt.
    pub fn run(&mut self) -> anyhow::Result<Receipt> {
        let session = self.run_without_proving()?;
        let prove_info = session.prove()?;
        Ok(prove_info.receipt)
    }
}

impl<'a> ZkvmHost for Risc0Host<'a> {
    type Guest = Risc0Guest;

    fn add_hint(&mut self, item: Vec<u8>) {
        // write buf
        self.env.extend(item);
    }

    fn simulate_with_hints(&mut self) -> Self::Guest {
        Risc0Guest::with_hints(std::mem::take(&mut self.env))
    }

    fn run(&mut self, with_proof: bool) -> Result<Proof, anyhow::Error> {
        if with_proof {
            let receipt = self.run()?;
            let data = bincode::serialize(&receipt)?;
            Ok(Proof::Full(data))
        } else {
            let session = self.run_without_proving()?;
            let data = bincode::serialize(&session.journal.expect("Journal shouldn't be empty"))?;
            Ok(Proof::PublicInput(data))
        }
    }

    fn extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        proof: &Proof,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let journal = match proof {
            Proof::PublicInput(journal) => {
                let journal: Journal = bincode::deserialize(journal)?;
                journal
            }
            Proof::Full(data) => {
                let receipt: Receipt = bincode::deserialize(data)?;
                receipt.journal
            }
        };
        Ok(BorshDeserialize::try_from_slice(&journal.bytes)?)
    }

    fn recover_proving_sessions(&self) -> Result<Vec<Proof>, anyhow::Error> {
        unimplemented!()
    }
}

impl<'host> Zkvm for Risc0Host<'host> {
    type CodeCommitment = Risc0MethodId;

    type Error = anyhow::Error;

    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<Vec<u8>, Self::Error> {
        verify_from_slice(serialized_proof, code_commitment)
    }

    fn verify_and_extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let output = Self::verify(serialized_proof, code_commitment)?;
        Ok(BorshDeserialize::deserialize(&mut &*output)?)
    }
}

/// A verifier for Risc0 proofs.
pub struct Risc0Verifier;

impl Zkvm for Risc0Verifier {
    type CodeCommitment = Risc0MethodId;

    type Error = anyhow::Error;

    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<Vec<u8>, Self::Error> {
        verify_from_slice(serialized_proof, code_commitment)
    }

    fn verify_and_extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let output = Self::verify(serialized_proof, code_commitment)?;
        Ok(BorshDeserialize::deserialize(&mut &*output)?)
    }
}

fn verify_from_slice(
    serialized_proof: &[u8],
    code_commitment: &Risc0MethodId,
) -> Result<Vec<u8>, anyhow::Error> {
    let Risc0Proof {
        receipt, journal, ..
    } = bincode::deserialize(serialized_proof)?;

    // after upgrade to risc0, verify is now in type Receipt
    // unless we change trait return types we have to clone here.
    let receipt: Receipt = Receipt::new(receipt, journal.to_vec());

    receipt.verify(code_commitment.0)?;

    Ok(journal.to_vec())
}

/// A convenience type which contains the same data a Risc0 [`Receipt`] but borrows the journal
/// data. This allows us to avoid one unnecessary copy during proof verification.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Risc0Proof<'a> {
    /// The cryptographic data certifying the execution of the program.
    pub receipt: InnerReceipt,
    /// The public outputs produced by the program execution.
    pub journal: &'a [u8],
}
