use std::sync::Arc;

use anyhow::Context;
use sov_db::{
    ledger_db::{BonsaiLedgerOps, LedgerDB},
    schema::types::{BonsaiSession, BonsaiSessionKind},
};
use sov_rollup_interface::zk::{ProofWithJob, ReceiptType};
use sp1_sdk::{
    network::B256, NetworkProver, Prover, ProverClient, SP1ProofMode, SP1ProofWithPublicValues,
    SP1ProvingKey, SP1Stdin, SP1VerifyingKey,
};
use tokio::sync::oneshot;
use tracing::error;
use uuid::Uuid;

#[derive(Clone)]
pub struct SuccinctProver {
    client: Arc<NetworkProver>,
    pk: SP1ProvingKey,
    vk: SP1VerifyingKey,
    ledger_db: LedgerDB,
}

impl SuccinctProver {
    pub fn new(elf: Vec<u8>, ledger_db: LedgerDB) -> Self {
        let client = ProverClient::builder().network().build();
        let (pk, vk) = client.setup(&elf);

        Self {
            client: Arc::new(client),
            pk,
            vk,
            ledger_db,
        }
    }

    pub fn prove(
        &self,
        job_id: Uuid,
        inputs: Vec<Vec<u8>>,
        receipt_type: ReceiptType,
    ) -> anyhow::Result<oneshot::Receiver<ProofWithJob>> {
        let mut stdin = SP1Stdin::new();

        for input in inputs {
            stdin.write_vec(input);
        }

        let mode = match receipt_type {
            ReceiptType::Groth16 => SP1ProofMode::Groth16,
            ReceiptType::Succinct => SP1ProofMode::Compressed,
        };

        let request_id = self
            .client
            .prove(&self.pk, &stdin)
            .mode(mode)
            .skip_simulation(true)
            .request()?;

        let db_session = BonsaiSession {
            kind: BonsaiSessionKind::StarkSession(request_id.to_string()),
            image_id: [0; 32],
            receipt_type,
        };
        self.ledger_db
            .upsert_pending_bonsai_session(job_id, db_session)
            .context("Failed to upsert SP1 session")?;

        let rx = self.spawn_handler(job_id, request_id);

        Ok(rx)
    }

    pub fn verify_proof(&self, proof: SP1ProofWithPublicValues) -> anyhow::Result<()> {
        self.client.verify(&proof, &self.vk)?;
        Ok(())
    }

    fn spawn_handler(&self, job_id: Uuid, request_id: B256) -> oneshot::Receiver<ProofWithJob> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            match this.client.wait_proof(request_id, None).await {
                Ok(proof) => {
                    let serialized_proof =
                        bincode::serialize(&proof).expect("Receipt serialization cannot fail");

                    // Do not remove pending bonsai session if we couldn't send the proof to caller.
                    // On restart we can again try to resend.
                    let Ok(_) = tx.send(ProofWithJob {
                        job_id,
                        proof: serialized_proof,
                    }) else {
                        error!("SP1 proof receiver channel is closed");
                        return;
                    };

                    if let Err(e) = this.ledger_db.remove_pending_bonsai_session(job_id) {
                        error!(
                            "Failed to remove pending bonsai session job: {} err={}",
                            job_id, e
                        );
                    }
                }
                Err(e) => error!(
                    "Failed to handle SP1 proving session job: {} err={}",
                    job_id, e
                ),
            }
        });

        rx
    }
}
