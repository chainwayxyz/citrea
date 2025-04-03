use std::env;
use std::path::PathBuf;

use anyhow::Context;
use rand::Rng;
use risc0_zkvm::{AssumptionReceipt, ExecutorEnvBuilder, ExternalProver, Prover, ProverOpts};
use sov_rollup_interface::zk::ReceiptType;
use sov_rollup_interface::Network;
use tokio::sync::oneshot;
use tracing::error;
use uuid::Uuid;

use super::{ProveInfo, SessionStats};

#[derive(Clone)]
pub struct LocalProver {
    dev_mode: bool,
    prove_sampling: Option<u64>,
    r0vm_path: PathBuf,
    #[cfg_attr(not(feature = "testing"), allow(unused))]
    network: Network,
}

impl LocalProver {
    pub fn new(prove_sampling: Option<u64>, network: Network) -> Self {
        assert!(
            env::var("RISC0_PROVER").map_or(true, |prover| prover == "ipc"),
            "Only supported RISC0_PROVER for LocalProver is ipc"
        );

        let dev_mode = env::var("RISC0_DEV_MODE").is_ok();
        if dev_mode {
            assert!(
                prove_sampling.is_none(),
                "Dev mode and prove sampling should not exist together"
            );
        }

        let r0vm_path = get_r0vm_path().expect("Could not get r0vm path");

        Self {
            dev_mode,
            prove_sampling,
            r0vm_path,
            network,
        }
    }

    pub fn prove(
        &self,
        job_id: Uuid,
        elf: Vec<u8>,
        input: Vec<u8>,
        assumptions: Vec<AssumptionReceipt>,
        receipt_type: ReceiptType,
    ) -> anyhow::Result<oneshot::Receiver<ProveInfo>> {
        // Set dev mode if not in already dev mode globally, and random sampling is non-zero
        if !self.dev_mode {
            if let Some(sampling) = self.prove_sampling {
                if sampling != 0 {
                    if rand::thread_rng().gen_range(0..sampling) != 0 {
                        // TODO: bug here... this is never unset, so it will never actually prove even if sampling hits
                        env::set_var("RISC0_DEV_MODE", "1");
                    }
                }
            }
        }

        // std::fs::write("kumquat-input.bin", &input).unwrap();

        let prover_opts = match receipt_type {
            ReceiptType::Groth16 => ProverOpts::groth16(),
            ReceiptType::Succinct => ProverOpts::succinct(),
        };

        tracing::info!("Starting local risc0 proving, job_id={}", job_id);

        let this = self.clone();
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            match this.handle_prove(elf, input, assumptions, prover_opts) {
                Ok(info) => {
                    let _ = tx.send(info);
                }
                Err(e) => error!("Local proving error: {}", e),
            }
        });

        Ok(rx)
    }

    fn handle_prove(
        &self,
        elf: Vec<u8>,
        input: Vec<u8>,
        assumptions: Vec<AssumptionReceipt>,
        prover_opts: ProverOpts,
    ) -> anyhow::Result<ProveInfo> {
        let assumptions_len = assumptions.len();

        let mut env = ExecutorEnvBuilder::default();
        // Add assumptions
        for assumption in assumptions {
            env.add_assumption(assumption);
        }

        tracing::debug!("{:?} assumptions added to the env", assumptions_len);

        #[cfg(feature = "testing")]
        {
            // If we are testing, set guest env var to enable dev mode so that it verifies fake receipts
            env.env_var("RISC0_DEV_MODE", "1");

            match self.network {
                Network::Nightly => {}
                Network::TestNetworkWithForks => {
                    env.env_var("ALL_FORKS", "1");
                }
                _ => panic!("Invalid network in testing feature!"),
            }
        }

        // Add input
        let env = env.write_slice(&input).build().unwrap();

        let prover = ExternalProver::new("ipc", self.r0vm_path.as_path());
        let prove_info = prover
            .prove_with_opts(env, &elf, &prover_opts)
            .context("Local risc0 proving failed")?;

        Ok(ProveInfo {
            receipt: prove_info.receipt,
            stats: SessionStats {
                segments: prove_info.stats.segments,
                total_cycles: prove_info.stats.total_cycles,
                user_cycles: prove_info.stats.user_cycles,
                paging_cycles: prove_info.stats.paging_cycles,
                reserved_cycles: prove_info.stats.reserved_cycles,
            },
        })
    }
}

// Copy-pasta from risc0_zkvm
fn get_r0vm_path() -> anyhow::Result<PathBuf> {
    if let Ok(path) = env::var("RISC0_SERVER_PATH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
    }

    let mut version = risc0_zkvm::get_version()?;
    tracing::debug!("version: {version}");

    if let Ok(rzup) = rzup::Rzup::new() {
        if let Ok(dir) = rzup.get_version_dir(&rzup::Component::R0Vm, &version) {
            return Ok(dir.join("r0vm"));
        }

        // Try again, but with these fields stripped
        version.patch = 0;
        version.build = Default::default();

        if let Ok(dir) = rzup.get_version_dir(&rzup::Component::R0Vm, &version) {
            return Ok(dir.join("r0vm"));
        }
    }

    Ok("r0vm".into())
}
