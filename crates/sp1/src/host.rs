//! SP1 execution and proving backend.
use borsh::BorshDeserialize;
use citrea_common::config::ProverGuestRunConfig;
use citrea_common::sp1::SP1HostConfig;
use sov_rollup_interface::zk::{
    Proof, ProofWithJob, ProvingSessionInfo, ReceiptType, Zkvm, ZkvmHost,
};
use sov_rollup_interface::Network;
use sp1_sdk::{Elf, HashableKey, Prover, ProverClient, ProvingKey, SP1Stdin};
use tokio::sync::oneshot;
use tracing::Instrument;
use uuid::Uuid;

use crate::guest::SP1Guest;
use crate::succinct_network::{prove_on_network, FIRST_OFFER_PERCENT};
use crate::utils::{execution_stats, record_execution};
use crate::{ProgramVKeyHash, SP1Proof};

/// Adds the proofs a guest verifies after its input. LCP recursion takes the native witness of
/// each compressed proof. A guest that accepts a mock receipt checks no witness for it, so mock
/// receipts add none, whether the job itself proves or only executes: with fake proof sampling,
/// or after a switch from `execute` to `prove`, a proven LCP follows a mock one. Mainnet guests
/// reject mock receipts, so there a mock assumption fails here instead of in the guest.
/// The separate witness stream is populated through SP1 6.10.0's [SP1Stdin::write_proof()].
///
/// [SP1Stdin::write_proof()]: https://github.com/succinctlabs/sp1/blob/d83ed91f96701209613720708f36ffce0e98ed33/crates/core/machine/src/io.rs#L60-L66
fn write_assumptions(
    stdin: &mut SP1Stdin,
    assumptions: Vec<Vec<u8>>,
    allow_mock: bool,
) -> anyhow::Result<()> {
    for assumption in assumptions {
        match SP1Proof::try_from_slice(&assumption)? {
            SP1Proof::Compressed { proof, .. } => {
                let vk: sp1_sdk::SP1VerifyingKey = bincode::deserialize(&proof.vkey)?;
                anyhow::ensure!(vk.hash_u32() == proof.native_vkey, "LCP key mismatch");
                let inner: sp1_sdk::SP1Proof = bincode::deserialize(&proof.proof)?;
                let sp1_sdk::SP1Proof::Compressed(inner) = inner else {
                    anyhow::bail!("LCP must be compressed");
                };
                stdin.write_proof(*inner, vk.vk);
            }
            SP1Proof::Mock { .. } if allow_mock => {}
            SP1Proof::Mock { .. } => anyhow::bail!("Mock LCP assumptions are forbidden on mainnet"),
            SP1Proof::Groth16 { .. } => anyhow::bail!("Invalid LCP assumption type"),
        }
    }
    Ok(())
}

/// Whether a prover in `proving_mode` answers some jobs with mock proofs. With fake proofs, a
/// sampling number of 0 or 1 proves every job.
fn mocks_jobs(proving_mode: ProverGuestRunConfig, proof_sampling_number: usize) -> bool {
    match proving_mode {
        ProverGuestRunConfig::Execute => true,
        ProverGuestRunConfig::ProveWithFakeProofs => proof_sampling_number > 1,
        ProverGuestRunConfig::Skip | ProverGuestRunConfig::Prove => false,
    }
}

#[derive(Clone)]
pub struct SP1Host {
    input: Vec<u8>,
    assumptions: Vec<Vec<u8>>,
    config: SP1HostConfig,
    network: Network,
}
impl SP1Host {
    pub fn new(network: Network, config: SP1HostConfig) -> Self {
        Self {
            input: vec![],
            assumptions: vec![],
            config,
            network,
        }
    }

    /// Proofs are only requested on Succinct's network, so a prover that proves cannot work
    /// with request settings that leave every request without a prover, or with a missing or
    /// invalid NETWORK_PRIVATE_KEY, and mainnet, which rejects mock proofs, needs a real proof
    /// of every job. Panics at startup instead of failing every proving job.
    pub async fn require_network_proving(
        &self,
        proving_mode: ProverGuestRunConfig,
        proof_sampling_number: usize,
    ) {
        assert!(
            self.network != Network::Mainnet || !mocks_jobs(proving_mode, proof_sampling_number),
            "Mainnet rejects mock proofs, so a mainnet prover must prove every job; got {proving_mode:?} with proof_sampling_number {proof_sampling_number}"
        );
        if matches!(
            proving_mode,
            ProverGuestRunConfig::Skip | ProverGuestRunConfig::Execute
        ) {
            return;
        }
        let request = self.config.network_request;
        assert!(
            request.no_bid_raise_percent > 100,
            "sp1_host.network_request.no_bid_raise_percent must be above 100, got {}",
            request.no_bid_raise_percent
        );
        assert!(
            request.max_usd_per_billion_pgu.is_finite() && request.max_usd_per_billion_pgu > 0.0,
            "sp1_host.network_request.max_usd_per_billion_pgu must be above 0, got {}",
            request.max_usd_per_billion_pgu
        );
        assert!(
            request.max_price_percent >= FIRST_OFFER_PERCENT,
            "sp1_host.network_request.max_price_percent must be at least {FIRST_OFFER_PERCENT}, got {}",
            request.max_price_percent
        );
        // The SDK cancels a request still unassigned after the auction timeout, and none is
        // assigned before the minimum auction period ends.
        assert!(
            request.auction_timeout_secs > request.min_auction_period_secs,
            "sp1_host.network_request.auction_timeout_secs must be longer than min_auction_period_secs, got {} and {}",
            request.auction_timeout_secs,
            request.min_auction_period_secs
        );
        assert!(
            request.deadline_percent > 0,
            "sp1_host.network_request.deadline_percent must be above 0"
        );
        // Panics on a missing or malformed key. Building the client does not contact the network.
        let _ = ProverClient::builder().network().build().await;
    }
}
#[async_trait::async_trait]
impl ZkvmHost for SP1Host {
    fn add_hint(&mut self, item: Vec<u8>) {
        self.input.extend_from_slice(&item);
    }
    fn add_assumption(&mut self, proof: Vec<u8>) {
        self.assumptions.push(proof);
    }
    async fn run(
        &mut self,
        job_id: Uuid,
        elf: Vec<u8>,
        program: ProgramVKeyHash,
        receipt_type: ReceiptType,
        with_prove: bool,
    ) -> anyhow::Result<oneshot::Receiver<ProofWithJob>> {
        let mode = match receipt_type {
            ReceiptType::Groth16 => sp1_sdk::SP1ProofMode::Groth16,
            ReceiptType::Succinct => sp1_sdk::SP1ProofMode::Compressed,
        };
        let input = std::mem::take(&mut self.input);
        let assumptions = std::mem::take(&mut self.assumptions);
        let mock = !with_prove;
        anyhow::ensure!(
            !mock || self.network != Network::Mainnet,
            "Mock proving is forbidden on mainnet"
        );
        let request = self.config.network_request;
        // Guest stdin layout, see docs/sp1-recursion.md.
        let mut stdin = SP1Stdin::new();
        stdin.write_vec(input);
        write_assumptions(&mut stdin, assumptions, self.network != Network::Mainnet)?;
        if let Some(dir) = &self.config.tx_backup_dir {
            std::fs::create_dir_all(dir)?;
            // The complete stdin, so the session replays as is.
            std::fs::write(
                dir.join(format!("{job_id}-sp1-stdin.bin")),
                bincode::serialize(&stdin)?,
            )?;
        }
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let result: anyhow::Result<ProofWithJob> = async {
                let elf = Elf::from(elf);
                let (proof, info) = if mock {
                    tracing::info!(%job_id, "Executing SP1 guest");
                    // No key setup: `program` is the pinned key of `elf`, checked by verifiers.
                    let client = ProverClient::builder().mock().build().await;
                    let (public_values, report) =
                        client.execute(elf, stdin).calculate_gas(true).await?;
                    anyhow::ensure!(
                        report.exit_code == 0,
                        "SP1 guest exited with code {}",
                        report.exit_code
                    );
                    let stats = execution_stats(&report)?;
                    record_execution(&stats);
                    (
                        SP1Proof::Mock {
                            program,
                            public_values: public_values.to_vec(),
                        },
                        ProvingSessionInfo::LocalExecution(stats),
                    )
                } else {
                    let client = ProverClient::builder().network().build().await;
                    let pk = client.setup(elf).await?;
                    anyhow::ensure!(
                        pk.verifying_key().hash_u32() == program,
                        "SP1 ELF does not match its pinned program key"
                    );
                    // The retry policy blocks between requests, and SDK verification is
                    // synchronous; keep both off Tokio's worker threads, in the job's span.
                    let span = tracing::Span::current();
                    let (proof, session, pk) =
                        tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                            let _span = span.enter();
                            let (proof, session) =
                                prove_on_network(&client, &pk, stdin, mode, &request)?;
                            client.verify(&proof, pk.verifying_key(), None)?;
                            Ok((proof, session, pk))
                        })
                        .await??;
                    let vk = pk.verifying_key();
                    // `client.verify` accepts any variant. Reject a proof of another mode here,
                    // before it is wrapped and persisted under the requested one.
                    anyhow::ensure!(
                        match receipt_type {
                            ReceiptType::Groth16 =>
                                matches!(proof.proof, sp1_sdk::SP1Proof::Groth16(_)),
                            ReceiptType::Succinct =>
                                matches!(proof.proof, sp1_sdk::SP1Proof::Compressed(_)),
                        },
                        "SP1 network returned a proof of another mode than {receipt_type:?}"
                    );
                    let proof = match receipt_type {
                        ReceiptType::Groth16 => SP1Proof::Groth16 {
                            proof: proof.bytes(),
                            public_values: proof.public_values.to_vec(),
                        },
                        ReceiptType::Succinct => SP1Proof::Compressed {
                            proof: sov_rollup_interface::zk::compressed::CompressedProof {
                                native_vkey: vk.hash_u32(),
                                proof: bincode::serialize(&proof.proof)?,
                                vkey: bincode::serialize(vk)?,
                            },
                            public_values: proof.public_values.to_vec(),
                        },
                    };
                    // `client.verify` does not cover everything `proof.bytes()` carries (the
                    // Groth16 vkey hash prefix, a TEE prefix). Verify what gets persisted, the
                    // way its consumers will, so a bad response fails this job here.
                    // Groth16 only: a compressed envelope is verifiable only in a guest, and
                    // adds nothing beyond `native_vkey`, checked against `program` above.
                    let proof = if matches!(proof, SP1Proof::Groth16 { .. }) {
                        tokio::task::spawn_blocking(move || {
                            proof.verify(&program, false).map(|()| proof)
                        })
                        .await??
                    } else {
                        proof
                    };
                    (proof, ProvingSessionInfo::SuccinctNetwork(session))
                };
                Ok(ProofWithJob {
                    job_id,
                    proof: borsh::to_vec(&proof)?,
                    info,
                })
            }
            .instrument(tracing::info_span!("sp1_proving_job", %job_id))
            .await;
            match result {
                Ok(proof) => {
                    let _ = tx.send(proof);
                }
                Err(error) => tracing::error!(%job_id, %error, "SP1 proving failed"),
            }
        });
        Ok(rx)
    }
    fn extract_output<T: BorshDeserialize>(proof: &Proof) -> anyhow::Result<T> {
        Self::deserialize_output(&Self::extract_raw_output(proof)?)
    }
    fn recursive_proof_hint(proof: &[u8]) -> anyhow::Result<Vec<u8>> {
        let proof = SP1Proof::try_from_slice(proof)?;
        anyhow::ensure!(
            !matches!(proof, SP1Proof::Groth16 { .. }),
            "LCP must be compressed"
        );
        Ok(borsh::to_vec(&proof.guest_hint())?)
    }
}
impl Zkvm for SP1Host {
    type CodeCommitment = ProgramVKeyHash;
    type Error = anyhow::Error;
    fn verify(proof: &[u8], program: &ProgramVKeyHash, allow_mock: bool) -> anyhow::Result<()> {
        SP1Guest::verify(proof, program, allow_mock)
    }
    fn extract_raw_output(proof: &[u8]) -> anyhow::Result<Vec<u8>> {
        SP1Guest::extract_raw_output(proof)
    }
    fn deserialize_output<T: BorshDeserialize>(journal: &[u8]) -> anyhow::Result<T> {
        SP1Guest::deserialize_output(journal)
    }
    fn verify_and_deserialize_output<T: BorshDeserialize>(
        proof: &[u8],
        program: &ProgramVKeyHash,
        allow_mock: bool,
    ) -> anyhow::Result<T> {
        SP1Guest::verify_and_deserialize_output(proof, program, allow_mock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[should_panic(expected = "no_bid_raise_percent must be above 100, got 100")]
    async fn proving_with_prices_that_never_rise_fails_at_startup() {
        let mut config = SP1HostConfig::default();
        config.network_request.no_bid_raise_percent = 100;
        let host = SP1Host::new(Network::Nightly, config);
        // Execution checks neither the request settings nor the key.
        host.require_network_proving(ProverGuestRunConfig::Execute, 0)
            .await;
        host.require_network_proving(ProverGuestRunConfig::Prove, 0)
            .await;
    }

    #[test]
    fn only_provers_that_prove_every_job_can_run_on_mainnet() {
        use ProverGuestRunConfig::*;
        for (mode, sampling, mocks) in [
            (Skip, 0, false),
            (Execute, 0, true),
            (Prove, 10, false),
            // The sampling number makes a fake proof of all but one in that many jobs.
            (ProveWithFakeProofs, 0, false),
            (ProveWithFakeProofs, 1, false),
            (ProveWithFakeProofs, 2, true),
        ] {
            assert_eq!(mocks_jobs(mode, sampling), mocks, "{mode:?} {sampling}");
        }
    }

    /// A mock previous LCP adds no recursion witness. Jobs take it wherever guests accept mock
    /// receipts, so a proven LCP can follow a mock one; mainnet and Groth16 are refused.
    #[test]
    fn mock_assumptions_add_no_witness() {
        let mock = borsh::to_vec(&SP1Proof::Mock {
            program: [1; 8],
            public_values: vec![2],
        })
        .unwrap();
        let mut stdin = SP1Stdin::new();
        write_assumptions(&mut stdin, vec![mock.clone()], true).unwrap();
        assert!(stdin.proofs.is_empty() && stdin.buffer.is_empty());

        let error = write_assumptions(&mut stdin, vec![mock], false).unwrap_err();
        assert!(
            error.to_string().contains("forbidden on mainnet"),
            "{error}"
        );

        let groth16 = borsh::to_vec(&SP1Proof::Groth16 {
            proof: vec![],
            public_values: vec![],
        })
        .unwrap();
        let error = write_assumptions(&mut stdin, vec![groth16], true).unwrap_err();
        assert!(
            error.to_string().contains("Invalid LCP assumption type"),
            "{error}"
        );
    }

    #[tokio::test]
    #[should_panic(expected = "Mainnet rejects mock proofs")]
    async fn mainnet_execution_fails_at_startup() {
        SP1Host::new(Network::Mainnet, SP1HostConfig::default())
            .require_network_proving(ProverGuestRunConfig::Execute, 0)
            .await;
    }
}
