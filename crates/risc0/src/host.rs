//! This module implements the [`ZkvmHost`] trait for the RISC0 VM.
use borsh::{BorshDeserialize, BorshSerialize};
use metrics::histogram;
use risc0_zkp::verify::VerificationError;
use risc0_zkvm::sha::Digest;
use risc0_zkvm::{
    compute_image_id, default_prover, AssumptionReceipt, ExecutorEnvBuilder, ProveInfo, ProverOpts,
    VerifierContext,
};
use sov_db::ledger_db::LedgerDB;
use sov_rollup_interface::zk::{Proof, Zkvm, ZkvmHost};
use sov_rollup_interface::Network;
use tracing::{debug, info};

use crate::guest::Risc0Guest;
use crate::receipt_from_proof;

type StarkSessionId = String;
type SnarkSessionId = String;

/// Bonsai sessions to be recovered in case of a crash.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub enum BonsaiSession {
    /// Stark session id if the prover crashed during stark proof generation.
    StarkSession(StarkSessionId),
    /// Both Stark and Snark session id if the prover crashed during stark to snarkconversion.
    SnarkSession(StarkSessionId, SnarkSessionId),
}

/// Recovered bonsai session.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct RecoveredBonsaiSession {
    /// Used for sending proofs in order
    pub id: u8,
    /// Recovered session
    pub session: BonsaiSession,
}

/// A [`Risc0BonsaiHost`] stores a binary to execute in the Risc0 VM and prove in the Risc0 Bonsai API.
#[derive(Clone)]
pub struct Risc0BonsaiHost {
    env: Vec<u8>,
    assumptions: Vec<AssumptionReceipt>,
    _ledger_db: LedgerDB,
    #[cfg(feature = "testing")]
    network: Network,
}

impl Risc0BonsaiHost {
    /// Create a new Risc0Host to prove the given binary.
    pub fn new(ledger_db: LedgerDB, _network: Network) -> Self {
        match std::env::var("RISC0_PROVER") {
            Ok(prover) => match prover.as_str() {
                "bonsai" => {
                    if std::env::var("BONSAI_API_URL").is_err()
                        || std::env::var("BONSAI_API_KEY").is_err()
                    {
                        panic!("Bonsai API URL and API key must be set when RISC0_PROVER is set to bonsai");
                    }
                }
                "local" => {}
                "ipc" => {
                    if std::env::var("RISC0_SERVER_PATH").is_err() {
                        panic!("RISC0_SERVER_PATH must be set when RISC0_PROVER is set to ipc");
                    }
                }
                _ => {
                    panic!("Invalid prover specified: {}", prover);
                }
            },
            Err(_) => {
                debug!("No prover specified.");

                if std::env::var("BONSAI_API_URL").is_ok()
                    && std::env::var("BONSAI_API_KEY").is_ok()
                {
                    panic!(
                        "Bonsai API URL and API key are set, but RISC0_PROVER is not set to bonsai"
                    );
                }
            }
        }

        Self {
            env: Default::default(),
            assumptions: vec![],
            _ledger_db: ledger_db,
            #[cfg(feature = "testing")]
            network: _network,
        }
    }
}

impl ZkvmHost for Risc0BonsaiHost {
    type Guest = Risc0Guest;

    fn add_hint(&mut self, item: Vec<u8>) {
        info!("Added hint to guest with size {}", item.len());

        // write buf
        self.env.extend_from_slice(&item);
    }

    /// Guest simulation (execute mode) is run inside the Risc0 VM locally
    fn simulate_with_hints(&mut self) -> Self::Guest {
        todo!("we don't use it yet")
    }

    fn add_assumption(&mut self, receipt_buf: Vec<u8>) {
        let receipt = receipt_from_proof(&receipt_buf).expect("Receipt should be valid");
        self.assumptions.push(receipt.into());
    }

    /// Only with_proof = true is supported.
    /// Proofs are created on the Bonsai API.
    fn run(
        &mut self,
        elf: Vec<u8>,
        with_proof: bool,
        // TODO: remove this when risc0 fixes its env.env_var bug
        _is_post_genesis_batch: bool,
    ) -> Result<Proof, anyhow::Error> {
        if !with_proof {
            if std::env::var("RISC0_PROVER") == Ok("bonsai".to_string()) {
                panic!("Bonsai prover requires with_proof to be true");
            }

            std::env::set_var("RISC0_DEV_MODE", "1");
        }

        let mut env = ExecutorEnvBuilder::default();
        for assumption in self.assumptions.iter() {
            env.add_assumption(assumption.clone());
        }

        tracing::debug!("{:?} assumptions added to the env", self.assumptions.len());

        #[cfg(feature = "testing")]
        {
            if _is_post_genesis_batch {
                let all_forks_flag = if self.network == Network::TestNetworkWithForks {
                    1u32
                } else {
                    0u32
                };

                env.write(&all_forks_flag)
                    .expect("Writing testing all forks flag should not fail");
            }
        }

        // std::fs::write("kumquat-input.bin", &self.env).unwrap();

        let env = env.write_slice(&self.env).build().unwrap();

        // The `RISC0_PROVER` environment variable, if specified, will select the
        // following [Prover] implementation:
        // * `bonsai`: [BonsaiProver] to prove on Bonsai.
        // * `local`: LocalProver to prove locally in-process. Note: this
        //   requires the `prove` feature flag.
        // * `ipc`: [ExternalProver] to prove using an `r0vm` sub-process. Note: `r0vm`
        //   must be installed. To specify the path to `r0vm`, use `RISC0_SERVER_PATH`.
        let prover = default_prover();

        tracing::info!("Starting risc0 proving");

        let ProveInfo { receipt, stats } =
            prover.prove_with_opts(env, &elf, &ProverOpts::groth16())?;

        histogram!("proving_session_cycle_count").record(stats.total_cycles as f64);

        tracing::info!("Execution Stats: {:?}", stats);

        let image_id = compute_image_id(&elf)?;

        receipt.verify(image_id)?;
        tracing::trace!("Calculated image id: {:?}", image_id.as_words());

        tracing::info!("Verified the receipt");

        // Instead of serializing full Receipt (as in PreFork2) we serialize only InnerReceipt:
        let serialized_receipt = bincode::serialize(&receipt.inner)?;

        // Cleanup env
        self.env.clear();

        // Cleanup assumptions
        self.assumptions.clear();

        Ok(serialized_receipt)
    }

    fn extract_output<T: BorshDeserialize>(proof: &Proof) -> Result<T, Self::Error> {
        let receipt = receipt_from_proof(proof)?;
        let journal = receipt.journal;

        Ok(T::try_from_slice(&journal.bytes)?)
    }

    fn recover_proving_sessions(&self) -> Result<Vec<Proof>, anyhow::Error> {
        Ok(Vec::new())

        // TODO: fix this https://github.com/chainwayxyz/citrea/issues/1410
        //
        // let sessions = self.ledger_db.get_pending_proving_sessions()?;
        // tracing::info!("Recovering {} bonsai sessions", sessions.len());
        // let mut proofs = Vec::new();
        // for session in sessions {
        //     let bonsai_session: RecoveredBonsaiSession = BorshDeserialize::try_from_slice(&session)
        //         .expect("Bonsai host should be able to recover bonsai sessions");

        //     tracing::info!("Recovering bonsai session: {:?}", bonsai_session);
        // match bonsai_session.session {
        //     BonsaiSession::StarkSession(stark_session) => {
        //         let _receipt = self.wait_for_receipt(&stark_session)?;
        //         let proof = self.wait_for_stark_to_snark_conversion(None, &stark_session)?;
        //         proofs.push(proof);
        //     }
        //     BonsaiSession::SnarkSession(stark_session, snark_session) => {
        //         let _receipt = self.wait_for_receipt(&stark_session)?;
        //         let proof = self
        //             .wait_for_stark_to_snark_conversion(Some(&snark_session), &stark_session)?;
        //         proofs.push(proof)
        //     }
        // }
        // }
        // Ok(proofs)
    }
}

impl Zkvm for Risc0BonsaiHost {
    type CodeCommitment = Digest;

    type Error = anyhow::Error;

    fn verify(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<(), Self::Error> {
        let receipt = receipt_from_proof(serialized_proof)?;

        let res = receipt.verify(*code_commitment);

        if let Err(VerificationError::InvalidProof) = res {
            tracing::warn!("Proof verification failed, trying risc0 1.0.5 verification...");

            receipt.verify_with_context(&verifier_context_pre_1_1_0(), *code_commitment)?;

            tracing::info!("Proof verification succeeded with risc0 1.0.5 context");

            return Ok(());
        }

        res?;

        Ok(())
    }

    fn extract_raw_output(serialized_proof: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let receipt = receipt_from_proof(serialized_proof)?;
        Ok(receipt.journal.bytes)
    }

    fn deserialize_output<T: BorshDeserialize>(journal: &[u8]) -> Result<T, Self::Error> {
        Ok(T::try_from_slice(journal)?)
    }

    fn verify_and_deserialize_output<T: BorshDeserialize>(
        serialized_proof: &[u8],
        code_commitment: &Self::CodeCommitment,
    ) -> Result<T, Self::Error> {
        let receipt = receipt_from_proof(serialized_proof)?;

        #[allow(clippy::clone_on_copy)]
        receipt.verify(code_commitment.clone())?;

        Ok(T::deserialize(&mut receipt.journal.as_ref())?)
    }

    fn verify_expected_to_fail(
        _serialized_proof: &[u8],
        _code_commitment: &Self::CodeCommitment,
    ) -> Result<(), Self::Error> {
        unimplemented!(
            "Risc0 host can use verify function to show proof fails. This function is not needed."
        )
    }
}

fn verifier_context_pre_1_1_0() -> VerifierContext {
    use std::collections::BTreeSet;

    use risc0_zkp::digest;
    use risc0_zkvm::{
        Groth16ReceiptVerifierParameters, SegmentReceiptVerifierParameters,
        SuccinctReceiptVerifierParameters,
    };

    let mut ctx = VerifierContext::default();

    ctx.segment_verifier_parameters = Some(SegmentReceiptVerifierParameters {
        control_ids: BTreeSet::from_iter(
            [
                digest!("55ba2d763ec3c016c0f97c298507115c77e0a25215e5771ba501d016edca522c"), //
                digest!("c265954c4dcb2155e041286a246bfe400ba9d042d919aa3cb1a299651f84c13e"), //
                digest!("467cd61da86f37347b45e64b5d4665308871bc301c67ba6c6d13c9470c3e4840"), //
                digest!("57b2031d3881e92b85d73d2d0800a223fdaccd5e7bdd0a569c10556ec138f551"), //
                digest!("c1f19103f8376c00fe20f62aa4370f628efe3a4a5eb1a5739466c944cf7dfe31"), //
                digest!("548ec1774c6c833b18db2e2a1464cb1923c6c721df87b437509ba87292d20529"), //
                digest!("ce535b3b10e4cc212842b90a918553633c4f5375dee51d4788798765df5a8750"), //
                digest!("7dea3854a91c906f92f23a291340066ecbd5375669fe752a5047c926e4d56747"), //
                digest!("dca31f53c5bf4c67ecdc9f1035cf5934072afc29573a1845100d6140befab657"), //
                digest!("12da4520930b1740810a69428c02fb2fcb586763a0e3794c45196608b594dd69"), //
                digest!("5c2dce7226ff9073b8e38919583c01375f11395111e9ae3bfd519b57f84a5e00"), //
            ]
            .into_iter()
            .chain([
                digest!("6d0ed860e3effc3cc00114075cb29630b583d227b5654adaf0e9a4e4926144a4"), //
                digest!("8f4880393dbb0dccf06e78081ca4f81b56e57ca5a0d056d927d41d1f19d0eb78"), //
                digest!("5461f6a04636ec3e513511de5b324e92ec027de3c3c2d5b56edcf28f21a2797e"), //
                digest!("aa0fe87d397a845d6c63b7896a031e2fd9d221e02625741ce631cf060542842d"), //
                digest!("fd2551902a296fcdc2d49ecbd7b2140b5b8adfb86023e4e2c1ad433e9d4e5487"), //
                digest!("204f8e50713cd5da7a41c128d1dd27b722ea0d6c21c785a9a608df13dcadc108"), //
                digest!("90d0d9c5bbb5ad02dd004a83e29a6ede8ed35d33a762bbf14f8fd323a8053fbf"), //
                digest!("3b652874501bcbb2d3283f4a6640fbc292f9db0c3353b1b5d058c79ab9e684ed"), //
                digest!("23ef25c5d5e356bab81c4905e499de9161596435839366c2b0e8fb3c6d8f2232"), //
                digest!("bb795263e615f72c0fb6b8d07c8dba82d1a8b5a53870b106ffe738a4f8943dc0"), //
                digest!("55330f0d062c6972bf3f65c4e5055544e20c9f776f6797f4428f7b3a6fbf0573"), //
            ])
            .chain([
                digest!("1f682e2ecfc82580667b8549ce548310f79f7055195d1f3a70d11565dd7c8311"), //
                digest!("66c3c1e1293ec0deea97cd1531a4fb202f7c57c3fa9908598519b12776272f37"), //
                digest!("e8a718749c38e77f1a52856568669d38591e5ee3deed15e251b4cd45994e56f7"), //
                digest!("3010f3679241489056004ab35e7b0c5feae8a6b45fe46f2c17e65e681e43ef25"), //
                digest!("a01d6a57f7aec62ffec3edcc5347c2acb88abdb0460e516d1b7d984f487dfce4"), //
                digest!("ba388a957a36a9a514fe5efe738f497fec585e267bcb6fb0a9d79b22f5cb34b1"), //
                digest!("e2fba32638e85de83c7ce06c41d48bb159efa0ec58de2e3ed4c172c7fc82b6e5"), //
                digest!("d9edf22d1c828087fec2fce4cf46261e8b6e8072b29f4beffbfc36309ae0e9d9"), //
                digest!("f04cfc7c358eaa225ee249e88b804a92679b43adf51b5cef1d0fef40c3afbc06"), //
                digest!("98b1e437c659b0435b5829a5d2fe697d08fc4b02641747d0f7d6b171b9c83415"), //
                digest!("68ada0a6c57d353b2a3645d42854365acd1aa453faebda9988b75c5802f4a1be"), //
            ]),
        ),
        ..Default::default()
    });

    ctx.succinct_verifier_parameters = Some(SuccinctReceiptVerifierParameters {
        control_root: digest!("a516a057c9fbf5629106300934d48e0e775d4230e41e503347cad96fcbde7e2e"),
        ..Default::default()
    });

    ctx.groth16_verifier_parameters = Some(Groth16ReceiptVerifierParameters {
        control_root: digest!("a516a057c9fbf5629106300934d48e0e775d4230e41e503347cad96fcbde7e2e"),
        bn254_control_id: digest!(
            "51b54a62f2aa599aef768744c95de8c7d89bf716e11b1179f05d6cf0bcfeb60e"
        ),
        ..Default::default()
    });

    ctx
}
