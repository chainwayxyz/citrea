use std::sync::Arc;

use sov_rollup_interface::{
    zk::{Proof, ProofWithJob, ReceiptType},
    Network,
};
use sp1_sdk::{
    EnvProver, SP1ProofMode, SP1ProofWithPublicValues, SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use tokio::sync::oneshot;
use tracing::error;
use uuid::Uuid;

#[derive(Clone)]
pub struct LocalProver {
    client: Arc<EnvProver>,
    pk: SP1ProvingKey,
    vk: SP1VerifyingKey,
    #[cfg_attr(not(feature = "testing"), allow(unused))]
    network: Network,
}

impl LocalProver {
    pub fn new(elf: Vec<u8>, network: Network) -> Self {
        let client = EnvProver::new();
        let (pk, vk) = client.setup(&elf);

        Self {
            client: Arc::new(client),
            pk,
            vk,
            network,
        }
    }

    pub fn prove(
        &self,
        job_id: Uuid,
        inputs: Vec<Vec<u8>>,
        receipt_type: ReceiptType,
    ) -> anyhow::Result<oneshot::Receiver<ProofWithJob>> {
        tracing::info!("Starting local SP1 proving, job_id={}", job_id);

        let mode = match receipt_type {
            ReceiptType::Groth16 => SP1ProofMode::Groth16,
            ReceiptType::Succinct => SP1ProofMode::Compressed,
        };

        let this = self.clone();
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn_blocking(move || match this.handle_prove(inputs, mode) {
            Ok(proof) => {
                let _ = tx.send(ProofWithJob { job_id, proof });
            }
            Err(e) => error!("Local proving error: {}", e),
        });

        Ok(rx)
    }

    pub fn verify_proof(&self, proof: SP1ProofWithPublicValues) -> anyhow::Result<()> {
        self.client.verify(&proof, &self.vk)?;
        Ok(())
    }

    fn handle_prove(&self, inputs: Vec<Vec<u8>>, mode: SP1ProofMode) -> anyhow::Result<Proof> {
        let mut stdin = SP1Stdin::new();

        for input in inputs {
            stdin.write_vec(input);
        }

        let proof = self.client.prove(&self.pk, &stdin).mode(mode).run()?;

        let serialized_proof =
            bincode::serialize(&proof).expect("Receipt serialization cannot fail");

        Ok(serialized_proof)
    }
}
