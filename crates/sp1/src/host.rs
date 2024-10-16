use borsh::{BorshDeserialize, BorshSerialize};
use sov_db::ledger_db::LedgerDB;
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};
use sp1_sdk::{ProverClient, SP1ProvingKey, SP1Stdin, SP1VerifyingKey};
use tracing::info;

use crate::guest::SP1Guest;
use crate::VerifyingKey;

pub struct SP1Host {
    client: ProverClient,
    elf: &'static [u8],
    proving_key: SP1ProvingKey,
    verifying_key: SP1VerifyingKey,
    input_buf: Vec<u8>,
    ledger_db: LedgerDB,
}

impl Clone for SP1Host {
    fn clone(&self) -> Self {
        Self {
            client: ProverClient::new(),
            elf: self.elf,
            proving_key: self.proving_key.clone(),
            verifying_key: self.verifying_key.clone(),
            input_buf: self.input_buf.clone(),
            ledger_db: self.ledger_db.clone(),
        }
    }
}

impl SP1Host {
    /// Creates an [`SP1Host`] instance. The type of [`ProverClient`]
    /// is determined based on the SP1_PROVER environment variable.
    /// Possible values are `local`, `mock`, `network`.
    /// If set value is `network`, SP1_PRIVATE_KEY environment variable
    /// must also be set. Default is `local`
    pub fn new(elf: &'static [u8], ledger_db: LedgerDB) -> Self {
        let client = ProverClient::new();

        let (proving_key, verifying_key) = client.setup(elf);

        Self {
            client,
            elf,
            proving_key,
            verifying_key,
            input_buf: vec![],
            ledger_db,
        }
    }

    pub fn collect_input_buf(&mut self) -> SP1Stdin {
        // Write local buffer to guest stdin and clear local buffer
        let mut stdin = SP1Stdin::new();
        let input_buf = std::mem::take(&mut self.input_buf);
        stdin.write_vec(input_buf);
        stdin
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
            let proof_with_public_values = self
                .client
                .prove(&self.proving_key, stdin)
                .groth16()
                .run()?;
            info!("Successfully generated proof");

            self.client
                .verify(&proof_with_public_values, &self.verifying_key)?;
            info!("Successfully verified the proof");

            let data = bincode::serialize(&proof_with_public_values)
                .expect("SP1 zk proof serialization must not fail");
            Ok(Proof::Full(data))
        } else {
            let (public_values, report) = self.client.execute(self.elf, stdin).run()?;
            info!("Number of cycles: {}", report.total_instruction_count());

            let data = bincode::serialize(&public_values)
                .expect("SP1 zk public values serialization must not fail");
            Ok(Proof::PublicInput(data))
        }
    }

    fn extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        _proof: &Proof,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        todo!()
    }

    fn recover_proving_sessions(&self) -> Result<Vec<Proof>, anyhow::Error> {
        todo!()
    }
}

impl Zkvm for SP1Host {
    type CodeCommitment = VerifyingKey;
    type Error = anyhow::Error;

    fn verify(
        _serialized_proof: &[u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }

    fn verify_and_extract_output<Da: sov_rollup_interface::da::DaSpec, Root: BorshDeserialize>(
        _serialized_proof: &[u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<sov_rollup_interface::zk::StateTransition<Da, Root>, Self::Error> {
        todo!()
    }
}
