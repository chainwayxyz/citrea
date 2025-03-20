use std::env;

use borsh::BorshDeserialize;
use citrea_sp1_guest::SP1Guest;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::LedgerDB;
use sov_rollup_interface::zk::{Proof, ProofWithJob, ReceiptType, Zkvm, ZkvmHost};
use sp1_sdk::{
    cpu::execute::CpuExecuteBuilder, include_elf, network::B256, EnvProver, NetworkProver, Prover,
    ProverClient, SP1ProofWithPublicValues, SP1ProvingKey, SP1PublicValues, SP1Stdin,
    SP1VerificationError, SP1VerifyingKey,
};
use tokio::sync::oneshot;
use tracing::info;

pub use citrea_sp1_guest::VerifyingKey;

// It is safer to define ProverClient once globally, because all the SP1 api is
// built around the client, and creating multiple ProverClient in the lifespan
// of the program causes problems especially when ran with cuda feature enabled.
pub static CLIENT: Lazy<MaybeNetworkProverClient> = Lazy::new(MaybeNetworkProverClient::default);

pub const ELF: &[u8] = include_elf!("sp1-batch-prover-bitcoin");

#[derive(Clone)]
pub struct SP1Host {
    elf: &'static [u8],
    proving_key: SP1ProvingKey,
    verifying_key: SP1VerifyingKey,
    input_buf: Vec<u8>,
    ledger_db: LedgerDB,
}

impl SP1Host {
    /// Creates an [`SP1Host`] instance. The type of [`ProverClient`]
    /// is determined based on the `SP1_PROVER`` environment variable.
    /// Possible values are `local`, `mock`, `network`.
    /// If set value is `network`, `SP1_PRIVATE_KEY` environment variable
    /// must also be set. Default is `local`
    pub fn new(elf: &'static [u8], ledger_db: LedgerDB) -> Self {
        let (proving_key, verifying_key) = CLIENT.setup(elf);

        Self {
            elf,
            proving_key,
            verifying_key,
            input_buf: vec![],
            ledger_db,
        }
    }

    fn collect_input_buf(&mut self) -> SP1Stdin {
        // Write local buffer to guest stdin and clear local buffer
        let mut stdin = SP1Stdin::new();
        let input_buf = std::mem::take(&mut self.input_buf);
        stdin.write_vec(input_buf);
        stdin
    }

    fn generate_proof(&self, stdin: SP1Stdin) -> anyhow::Result<SP1ProofWithPublicValues> {
        // If prover is Succinct prover, we have to save the sessions to ledger db
        match &*CLIENT {
            MaybeNetworkProverClient::Network(network_prover) => {
                // Request for proof from Succinct
                let request_id = network_prover.prove(&self.proving_key, &stdin).request()?;
                // Save pending request id to db
                self.ledger_db
                    .add_pending_proving_session(request_id.to_vec())?;

                let proof = block_on(network_prover.wait_proof(request_id, None))?;

                // Remove pending request id from db, but do not abort if failed. We optimistically hope
                // that on the next restart we will see that it is finished and remove.
                if let Err(err) = self
                    .ledger_db
                    .remove_pending_proving_session(request_id.to_vec())
                {
                    tracing::error!("Failed to remove pending proving session: {}", err);
                }

                Ok(proof)
            }
            MaybeNetworkProverClient::Local(env_prover) => {
                env_prover.prove(&self.proving_key, &stdin).groth16().run()
            }
        }
    }
}

pub enum MaybeNetworkProverClient {
    Network(NetworkProver),
    Local(EnvProver),
}

impl Default for MaybeNetworkProverClient {
    fn default() -> Self {
        if env::var("SP1_PROVER").is_ok_and(|e| &e == "network") {
            Self::Network(ProverClient::builder().network().build())
        } else {
            Self::Local(EnvProver::new())
        }
    }
}

impl MaybeNetworkProverClient {
    pub fn setup(&self, elf: &[u8]) -> (SP1ProvingKey, SP1VerifyingKey) {
        match self {
            MaybeNetworkProverClient::Network(network_prover) => network_prover.setup(elf),
            MaybeNetworkProverClient::Local(env_prover) => env_prover.setup(elf),
        }
    }

    pub fn execute<'a>(&'a self, elf: &'a [u8], stdin: &SP1Stdin) -> CpuExecuteBuilder<'a> {
        match self {
            MaybeNetworkProverClient::Network(network_prover) => network_prover.execute(elf, stdin),
            MaybeNetworkProverClient::Local(env_prover) => env_prover.execute(elf, stdin),
        }
    }

    pub fn verify(
        &self,
        bundle: &SP1ProofWithPublicValues,
        vkey: &SP1VerifyingKey,
    ) -> Result<(), SP1VerificationError> {
        match self {
            MaybeNetworkProverClient::Network(network_prover) => {
                network_prover.verify(bundle, vkey)
            }
            MaybeNetworkProverClient::Local(env_prover) => env_prover.verify(bundle, vkey),
        }
    }
}

impl ZkvmHost for SP1Host {
    type Guest = SP1Guest;

    fn add_hint(&mut self, buf: Vec<u8>) {
        // write buf
        self.input_buf.extend_from_slice(&buf);

        info!("Added hint to guest with size {}", buf.len());
    }

    fn simulate_with_hints(&mut self) -> Self::Guest {
        unimplemented!("Simulate is not implemented for SP1")
    }

    fn run(
        &mut self,
        _job_id: uuid::Uuid,
        _elf: Vec<u8>,
        _receipt_type: ReceiptType,
        with_prove: bool,
    ) -> anyhow::Result<oneshot::Receiver<ProofWithJob>> {
        let stdin = self.collect_input_buf();

        if with_prove {
            let proof_with_public_values = self.generate_proof(stdin)?;
            info!("Successfully generated proof");

            CLIENT.verify(&proof_with_public_values, &self.verifying_key)?;
            info!("Successfully verified the proof");

            let data = bincode::serialize(&PublicValues::WithProof(proof_with_public_values))
                .expect("SP1 zk proof serialization must not fail");
            Ok(data)
        } else {
            let (public_values, report) = CLIENT.execute(self.elf, &stdin).run()?;
            info!("Number of cycles: {}", report.total_instruction_count());

            let data = bincode::serialize(&PublicValues::WithoutProof(public_values))
                .expect("SP1 zk public values serialization must not fail");
            Ok(data)
        }
    }

    fn extract_output<T: BorshDeserialize>(proof: &Proof) -> Result<T, Self::Error> {
        let public_values = bincode::deserialize::<PublicValues>(proof)?;

        let public_values = match public_values {
            PublicValues::WithProof(proof) => proof.public_values,
            PublicValues::WithoutProof(public_values) => public_values,
        };

        Ok(BorshDeserialize::try_from_slice(public_values.as_slice())?)
    }

    fn start_session_recovery(
        &self,
    ) -> Result<Vec<oneshot::Receiver<ProofWithJob>>, anyhow::Error> {
        Ok(vec![])
    }

    fn add_assumption(&mut self, _receipt_buf: Vec<u8>) {
        unimplemented!()
    }
}

impl Zkvm for SP1Host {
    type CodeCommitment = VerifyingKey;
    type Error = anyhow::Error;

    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<(), Self::Error> {
        let proof: SP1ProofWithPublicValues = bincode::deserialize(serialized_proof)?;

        CLIENT.verify(&proof, &code_commitment.0)?;

        Ok(())
    }

    fn extract_raw_output(_serialized_proof: &[u8]) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }

    fn deserialize_output<T: BorshDeserialize>(_journal: &[u8]) -> Result<T, Self::Error> {
        todo!()
    }

    fn verify_and_deserialize_output<T: BorshDeserialize>(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<T, Self::Error> {
        let proof: SP1ProofWithPublicValues = bincode::deserialize(serialized_proof)?;

        CLIENT.verify(&proof, &code_commitment.0)?;

        Ok(T::try_from_slice(proof.public_values.as_slice())?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PublicValues {
    WithProof(SP1ProofWithPublicValues),
    WithoutProof(SP1PublicValues),
}

fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
    use tokio::task::block_in_place;

    // Handle case if we're already in an tokio runtime.
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        block_in_place(|| handle.block_on(fut))
    } else {
        // Otherwise create a new runtime.
        let rt = tokio::runtime::Runtime::new().expect("Failed to create a new runtime");
        rt.block_on(fut)
    }
}
