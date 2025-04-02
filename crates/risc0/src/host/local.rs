use std::{env, sync::Arc};

use risc0_zkvm::{default_prover, AssumptionReceipt, ExternalProver, Prover, Receipt};
use sov_rollup_interface::zk::ReceiptType;
use tokio::sync::oneshot;
use uuid::Uuid;

#[derive(Clone)]
pub struct LocalProver {
    inner: Arc<dyn Prover>,
}

impl LocalProver {
    pub fn new() -> Self {
        if let Ok(prover) = env::var("RISC0_PROVER") {
            match prover.to_lowercase().as_str() {
                "ipc" => {
                    let r0vm_path = env::var("RISC0_SERVER_PATH").expect("RISC0_SERVER_PATH must be set when RISC0_PROVER is set to ipc")
                }
                p => panic!("Unsupported RISC0_PROVER for LocalProver: {}", p)
            }
        }

        assert!(
            env::var("RISC0_PROVER").map_or(true, |prover| prover != "bonsai"),
            "RISC0_PROVER must be explicitly set to bonsai"
        );
        let inner = default_prover();
        let p = ExternalProver::new("hey", "");
        Self { inner: Arc::new(p) }
    }

    pub fn prove(
        &self,
        job_id: Uuid,
        elf: Vec<u8>,
        input: Vec<u8>,
        assumptions: Vec<AssumptionReceipt>,
        receipt_type: ReceiptType,
    ) -> anyhow::Result<oneshot::Receiver<ProveInfo>> {
        todo!()
    }
}

pub struct ProveInfo {
    pub receipt: Receipt,
    pub stats: SessionStats,
}

pub struct SessionStats {
    pub segments: usize,
    pub total_cycles: u64,
    pub user_cycles: u64,
    pub paging_cycles: u64,
    pub reserved_cycles: u64,
}
