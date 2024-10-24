use borsh::{BorshDeserialize, BorshSerialize};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sov_db::ledger_db::{LedgerDB, ProvingServiceLedgerOps};
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};
use sp1_sdk::network_v2::proto::network::ProofMode;
use sp1_sdk::provers::ProverType;
use sp1_sdk::{
    block_on, CpuProver, HashableKey, NetworkProverV2, Prover, ProverClient,
    SP1ProofWithPublicValues, SP1ProvingKey, SP1PublicValues, SP1Stdin, SP1VerifyingKey,
};
use tracing::info;

use crate::guest::SP1Guest;

static CLIENT: Lazy<ProverClient> = Lazy::new(|| {
    ProverClient::new()
});

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

    fn is_succinct_prover(&self) -> bool {
        CLIENT.prover.id() == ProverType::Network
    }

    fn collect_input_buf(&mut self) -> SP1Stdin {
        // Write local buffer to guest stdin and clear local buffer
        let mut stdin = SP1Stdin::new();
        let input_buf = std::mem::take(&mut self.input_buf);
        stdin.write_vec(input_buf);
        stdin
    }

    fn wait_succinct_proof(
        &self,
        prover: &NetworkProverV2,
        request_id: Vec<u8>,
    ) -> anyhow::Result<SP1ProofWithPublicValues> {
        // Wait for proof
        let proof = block_on(prover.wait_proof(&request_id, None))?;
        // Remove pending request id from db
        self.ledger_db.remove_pending_proving_session(request_id)?;

        Ok(proof)
    }

    fn generate_proof(&self, stdin: SP1Stdin) -> anyhow::Result<SP1ProofWithPublicValues> {
        // If prover is Succinct prover, we have to save the
        // sessions to ledger db
        if self.is_succinct_prover() {
            // Recreate the NetworkProver due to the SP1 implementing
            // it as a trait, but we need concrete type's methods
            let prover = NetworkProverV2::new();

            // Request for proof from Succinct
            let request_id =
                block_on(prover.request_proof(self.elf, stdin, ProofMode::Groth16, None))?;
            // Save pending request id to db
            self.ledger_db
                .add_pending_proving_session(request_id.clone())?;

            self.wait_succinct_proof(&prover, request_id)
        } else {
            CLIENT.prove(&self.proving_key, stdin).groth16().run()
        }
    }
}

impl ZkvmHost for SP1Host {
    type Guest = SP1Guest;

    fn add_hint<T: BorshSerialize>(&mut self, item: T) {
        let buf = borsh::to_vec(&item).expect("Borsh hint serialization cannot fail");
        info!("Added hint to guest with size {}", buf.len());

        // write buf
        self.input_buf.extend_from_slice(&buf);
    }

    fn simulate_with_hints(&mut self) -> Self::Guest {
        unimplemented!("Simulate is not implemented for SP1")
    }

    fn run(&mut self, with_proof: bool) -> Result<Proof, anyhow::Error> {
        let stdin = self.collect_input_buf();

        if with_proof {
            let proof_with_public_values = self.generate_proof(stdin)?;
            info!("Successfully generated proof");

            CLIENT.verify(&proof_with_public_values, &self.verifying_key)?;
            info!("Successfully verified the proof");

            let data = bincode::serialize(&proof_with_public_values)
                .expect("SP1 zk proof serialization must not fail");
            Ok(Proof::Full(data))
        } else {
            let (public_values, report) = CLIENT.execute(self.elf, stdin).run()?;
            info!("Number of cycles: {}", report.total_instruction_count());

            let data = bincode::serialize(&public_values)
                .expect("SP1 zk public values serialization must not fail");
            Ok(Proof::PublicInput(data))
        }
    }

    fn extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        proof: &Proof,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let public_values = match proof {
            Proof::PublicInput(data) => {
                let public_values: SP1PublicValues = bincode::deserialize(data)?;
                public_values
            }
            Proof::Full(data) => {
                let proof: SP1ProofWithPublicValues = bincode::deserialize(data)?;
                proof.public_values
            }
        };

        Ok(BorshDeserialize::try_from_slice(public_values.as_slice())?)
    }

    fn recover_proving_sessions(&self) -> Result<Vec<Proof>, anyhow::Error> {
        // We can only recover if prover is configured to be Succinct
        if !self.is_succinct_prover() {
            return Ok(vec![]);
        }

        let request_ids = self.ledger_db.get_pending_proving_sessions()?;
        tracing::info!("Recovering {} Succinct sessions", request_ids.len());

        let prover = NetworkProverV2::new();
        let mut proofs = Vec::new();
        for request_id in request_ids {
            tracing::info!("Recovering Succinct session: {:?}", request_id);

            let proof_with_public_values = self.wait_succinct_proof(&prover, request_id)?;

            CLIENT.verify(&proof_with_public_values, &self.verifying_key)?;
            info!("Successfully verified the proof");

            let data = bincode::serialize(&proof_with_public_values)
                .expect("SP1 zk proof serialization must not fail");

            proofs.push(Proof::Full(data));
        }

        Ok(proofs)
    }
}

impl Zkvm for SP1Host {
    type CodeCommitment = VerifyingKey;
    type Error = anyhow::Error;

    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<Vec<u8>, Self::Error> {
        let proof: SP1ProofWithPublicValues = bincode::deserialize(serialized_proof)?;

        ProverClient::new().verify(&proof, &code_commitment.0)?;

        Ok(proof.public_values.to_vec())
    }

    fn verify_and_extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        let proof: SP1ProofWithPublicValues = bincode::deserialize(serialized_proof)?;

        ProverClient::new().verify(&proof, &code_commitment.0)?;

        Ok(BorshDeserialize::try_from_slice(
            proof.public_values.as_slice(),
        )?)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VerifyingKey(SP1VerifyingKey);

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = self.0.bytes32();
        write!(f, "VerifyingKey {{ SP1VerifyingKey {{ vk: {} }} }}", key)
    }
}

impl VerifyingKey {
    pub fn from_elf(elf: &[u8]) -> Self {
        let (_, vk) = CpuProver::new().setup(elf);
        Self(vk)
    }
}
