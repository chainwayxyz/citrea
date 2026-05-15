use std::time::Duration;

use anyhow::{anyhow, Context};
use bonsai_sdk::blocking::{Client, SessionId, SnarkId};
use bonsai_sdk::responses::SessionStats;
use citrea_common::config::risc0::BonsaiProverConfig;
use citrea_common::utils::is_dev_mode_enabled_via_environment;
use metrics::gauge;
use risc0_zkvm::{compute_image_id, AssumptionReceipt, Digest, InnerAssumptionReceipt, Receipt};
use sov_rollup_interface::zk::{
    BonsaiProvingSessionInfo, ProofWithJob, ProvingSessionInfo, ReceiptType,
};
use tokio::sync::oneshot;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Clone)]
pub struct BonsaiProver {
    client: Client,
}

impl BonsaiProver {
    pub fn new(config: BonsaiProverConfig) -> Self {
        assert!(
            !is_dev_mode_enabled_via_environment(),
            "RISC0_DEV_MODE should not be set for bonsai"
        );

        let client = Client::from_parts(config.api_url, config.api_key, risc0_zkvm::VERSION)
            .expect("Bonsai client build cannot fail");

        Self { client }
    }

    pub fn prove(
        &self,
        job_id: Uuid,
        elf: Vec<u8>,
        input: Vec<u8>,
        assumptions: Vec<AssumptionReceipt>,
        receipt_type: ReceiptType,
    ) -> anyhow::Result<oneshot::Receiver<ProofWithJob>> {
        // Upload image id
        let image_id = compute_image_id(&elf).expect("Invalid elf program");
        let image_id_hex = hex::encode(image_id);
        self.client
            .upload_img(&image_id_hex, elf)
            .context("Failed to upload img")?;

        // Upload input
        let input_id = self
            .client
            .upload_input(input)
            .context("Failed to upload input")?;

        // Upload assumptions
        let mut receipt_ids = vec![];
        for assumption in assumptions {
            let inner_receipt = get_inner_assumption_receipt(&assumption)?;
            let serialized_receipt = bincode::serialize(inner_receipt)?;
            let receipt_id = self
                .client
                .upload_receipt(serialized_receipt)
                .context("Failed to upload receipt")?;
            receipt_ids.push(receipt_id);
        }

        // Start bonsai stark proving session
        let session = self
            .client
            .create_session(image_id_hex, input_id, receipt_ids, false)
            .context("Failed to create session")?;
        info!(
            "Started bonsai proving session, job_id={} session_id={}",
            job_id, session.uuid
        );

        let rx = self.spawn_handler(job_id, session, image_id, receipt_type);

        Ok(rx)
    }

    /// Spawn a background handler to handle the stark session
    fn spawn_handler(
        &self,
        job_id: Uuid,
        session: SessionId,
        image_id: Digest,
        receipt_type: ReceiptType,
    ) -> oneshot::Receiver<ProofWithJob> {
        let this = self.clone();
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            match this
                .handle_session(job_id, session.clone(), image_id, receipt_type)
                .await
            {
                Ok((receipt, stats)) => {
                    let serialized_receipt = bincode::serialize(&receipt.inner)
                        .expect("Receipt serialization cannot fail");

                    let Ok(_) = tx.send(ProofWithJob {
                        job_id,
                        proof: serialized_receipt,
                        info: ProvingSessionInfo::Bonsai(BonsaiProvingSessionInfo {
                            session_id: session.uuid,
                            segments: stats.segments,
                            total_cycles: stats.total_cycles,
                            user_cycles: stats.cycles,
                            receipt_type,
                        }),
                    }) else {
                        error!("Bonsai proof receiver channel is closed");
                        return;
                    };
                }
                Err(e) => error!(
                    "Failed to handle Bonsai proving session job: {} err={}",
                    job_id, e
                ),
            }
        });

        rx
    }

    async fn handle_session(
        &self,
        job_id: Uuid,
        session: SessionId,
        image_id: Digest,
        receipt_type: ReceiptType,
    ) -> anyhow::Result<(Receipt, SessionStats)> {
        let (succinct_receipt, stats) = self.wait_stark_receipt(&session).await?;
        succinct_receipt
            .verify(image_id)
            .context("Failed to verify bonsai succinct proof")?;

        gauge!("proving_session_cycle_count").set(stats.total_cycles as f64);
        tracing::info!(
            "Execution Stats for job_id={}: total_cycles={} user_cycles={} segments={}",
            job_id,
            stats.total_cycles,
            stats.cycles,
            stats.segments,
        );

        if matches!(receipt_type, ReceiptType::Succinct) {
            return Ok((succinct_receipt, stats));
        }

        let snark_session = self.client.create_snark(session.uuid.clone())?;

        let groth16_receipt = self.wait_snark_receipt(&snark_session).await?;
        groth16_receipt
            .verify(image_id)
            .context("Failed to verify bonsai groth16 proof")?;

        Ok((groth16_receipt, stats))
    }

    async fn wait_stark_receipt(
        &self,
        session: &SessionId,
    ) -> anyhow::Result<(Receipt, SessionStats)> {
        let polling_interval = Duration::from_secs(1);
        loop {
            let res = session.status(&self.client)?;
            match res.status.as_str() {
                "RUNNING" => tokio::time::sleep(polling_interval).await,
                "SUCCEEDED" => {
                    let receipt_url = res.receipt_url.expect("Missing receipt url");
                    let stats = res.stats.expect("Missing stats object");

                    let receipt_buf = self
                        .client
                        .download(&receipt_url)
                        .context("Failed to download stark receipt")?;
                    let receipt: Receipt = bincode::deserialize(&receipt_buf)
                        .expect("Receipt deserialization cannot fail");

                    return Ok((receipt, stats));
                }
                _ => {
                    return Err(anyhow!(
                        "Bonsai stark proving session {} returned error: {} msg={:?}",
                        session.uuid,
                        res.status,
                        res.error_msg
                    ));
                }
            }
        }
    }

    async fn wait_snark_receipt(&self, session: &SnarkId) -> anyhow::Result<Receipt> {
        let polling_interval = Duration::from_secs(1);
        loop {
            let res = session.status(&self.client)?;
            match res.status.as_str() {
                "RUNNING" => tokio::time::sleep(polling_interval).await,
                "SUCCEEDED" => {
                    let receipt_url = res
                        .output
                        .expect("Bonsai returned success but provided no snark receipt");

                    let receipt_buf = self
                        .client
                        .download(&receipt_url)
                        .context("Failed to download snark receipt")?;
                    let receipt: Receipt = bincode::deserialize(&receipt_buf)
                        .expect("Receipt deserialization cannot fail");

                    return Ok(receipt);
                }
                _ => {
                    return Err(anyhow!(
                        "Bonsai snark proving session {} returned error: {} msg={:?}",
                        session.uuid,
                        res.status,
                        res.error_msg
                    ));
                }
            }
        }
    }
}

// Only proven assumptions that are succinct are supported by Bonsai.
fn get_inner_assumption_receipt(
    assumption: &AssumptionReceipt,
) -> anyhow::Result<&InnerAssumptionReceipt> {
    match assumption {
        AssumptionReceipt::Proven(receipt) => {
            if !matches!(receipt, InnerAssumptionReceipt::Succinct(_)) {
                return Err(anyhow!(
                    "Bonsai only supports succinct assumption receipts. \
                    Use `ProverOpts::succinct()` when proving any assumptions."
                ));
            };
            Ok(receipt)
        }
        AssumptionReceipt::Unresolved(_) => Err(anyhow!(
            "only proven assumptions can be uploaded to Bonsai."
        )),
    }
}
