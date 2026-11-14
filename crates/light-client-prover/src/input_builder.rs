//! Shared light client circuit input construction.

use std::collections::HashMap;

use citrea_common::LightClientProverConfig;
use citrea_primitives::forks::proof_guest_spec_id;
use citrea_primitives::risc0_cutoff::{risc0_cutoff, Risc0Cutoff};
use sov_db::ledger_db::LightClientProverLedgerOps;
use sov_modules_api::{SpecId, Zkvm};
use sov_prover_storage_manager::ProverStorage;
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use sov_rollup_interface::zk::ZkvmHost;
use sov_rollup_interface::Network;

use crate::circuit::initial_values::InitialValueProvider;
use crate::circuit::{LightClientProofCircuit, RunL1BlockResult};

/// Prepared light client circuit input and native state transition data.
pub(crate) struct PreparedLightClientCircuitInput<DS: DaSpec> {
    /// Spec ID used to select the light client proof circuit.
    pub(crate) spec_id: SpecId,
    /// Borsh-serializable input that can be passed to the light client circuit.
    pub(crate) circuit_input: LightClientCircuitInput<DS>,
    /// Host-only recursive proofs, in guest verification order.
    pub(crate) assumptions: Vec<Vec<u8>>,
    /// JMT state root after processing the L1 block.
    pub(crate) lcp_state_root: [u8; 32],
    /// Last verified L2 height after processing the L1 block.
    pub(crate) last_l2_height: u64,
    /// JMT storage changes. Must only be finalized after proof generation succeeds.
    pub(crate) change_set: ProverStorage,
    /// Last verified sequencer commitment index after processing the L1 block.
    pub(crate) last_sequencer_commitment_index: u32,
}

/// Builds light client circuit inputs from fetched L1 blocks.
pub(crate) struct LightClientInputBuilder<Da, Vm>
where
    Da: DaService,
    Vm: Zkvm,
    Network: InitialValueProvider<Da::Spec>,
{
    /// The Citrea network this input is built for.
    pub(crate) network: Network,
    /// RISC0 cutoff the first light client proof continues from. It is the one the guest is
    /// compiled with, so it is never taken from the environment like the other nodes' cutoff.
    pub(crate) risc0_cutoff: Option<Risc0Cutoff>,
    /// Native light client circuit runner used to produce witness data.
    pub(crate) circuit: LightClientProofCircuit<ProverStorage, Da::Spec, Vm>,
}

impl<Da, Vm> LightClientInputBuilder<Da, Vm>
where
    Da: DaService,
    Vm: ZkvmHost,
    Network: InitialValueProvider<Da::Spec>,
{
    /// Creates a builder for the given network with a reusable native circuit runner.
    pub(crate) fn new(network: Network) -> Self {
        Self {
            network,
            risc0_cutoff: risc0_cutoff(network),
            circuit: LightClientProofCircuit::new(),
        }
    }

    /// Builds the light client circuit input for an already fetched L1 block.
    ///
    /// The caller owns the returned state transition data and must only finalize its change set
    /// after the corresponding proof has been generated successfully.
    pub(crate) fn build_from_l1_block(
        &self,
        l1_block: &Da::FilteredBlock,
        storage: ProverStorage,
        prover_config: &LightClientProverConfig,
        da_service: &Da,
        ledger_db: &impl LightClientProverLedgerOps,
        code_commitments: &HashMap<SpecId, Vm::CodeCommitment>,
    ) -> anyhow::Result<PreparedLightClientCircuitInput<Da::Spec>> {
        let l1_height = l1_block.header().height();

        let (da_data, inclusion_proof, completeness_proof) =
            da_service.extract_relevant_blobs_with_proof(l1_block);

        let risc0_cutoff = self.risc0_cutoff.clone();
        if let Some(p0) = &risc0_cutoff {
            anyhow::ensure!(
                l1_height > p0.l1_height(),
                "L1 block #{l1_height} is proven by the RISC0 light client, start from a RISC0 light client prover database at L1 block #{}",
                p0.l1_height()
            );
        }

        let spec_id = proof_guest_spec_id();
        let light_client_proof_code_commitment = code_commitments
            .get(&spec_id)
            .ok_or_else(|| anyhow::anyhow!("Fork should have a guest code attached"))?;
        let light_client_proof_method_id: [u32; 8] =
            light_client_proof_code_commitment.clone().into();

        let previous_l1_height = l1_height.saturating_sub(1);
        let (previous_lcp_proof, previous_lcp_output) = match (
            ledger_db.get_light_client_proof_data_by_l1_height(previous_l1_height)?,
            risc0_cutoff,
        ) {
            // sp1 migration detection
            // The proof at L0 is the RISC0 light client's, so the first SP1 light client proof
            // has no previous proof. Like the guest, it continues from P0.
            (Some(_), Some(p0)) if previous_l1_height == p0.l1_height() => {
                tracing::warn!(
                    "Creating initial SP1 light client proof on L1 block #{}",
                    l1_height
                );
                (
                    None,
                    Some(p0.light_client_proof_output(light_client_proof_method_id)),
                )
            }
            (Some(data), _) => (
                Some(data.proof),
                Some(LightClientCircuitOutput::from(
                    data.light_client_proof_output,
                )),
            ),
            (None, None) if l1_height == prover_config.initial_da_height => {
                // first time proving a light client proof
                tracing::warn!(
                    "Creating initial light client proof on L1 block #{}",
                    l1_height
                );
                (None, None)
            }
            (None, _) => {
                anyhow::bail!(
                    "Missing previous light client proof for L1 block #{previous_l1_height} while building input for L1 block #{l1_height}"
                );
            }
        };

        let RunL1BlockResult {
            l2_state_root: _,
            lcp_state_root,
            last_l2_height,
            witness,
            change_set,
            last_sequencer_commitment_index,
        } = self.circuit.run_l1_block(
            self.network,
            storage,
            Default::default(),
            da_data,
            l1_block.header().clone(),
            previous_lcp_output,
            self.network.get_l2_genesis_root(),
            self.network.initial_batch_proof_method_ids().to_vec(),
            &self.network.batch_prover_da_public_key(),
            &self.network.sequencer_da_public_key(),
            &self.network.method_id_upgrade_authority_da_public_keys(),
        );

        let mut circuit_input = LightClientCircuitInput {
            inclusion_proof,
            completeness_proof,
            da_block_header: l1_block.header().clone(),
            light_client_proof_method_id,
            previous_light_client_proof: previous_lcp_proof,
            witness,
        };
        let mut assumptions = vec![];
        if let Some(previous) = &mut circuit_input.previous_light_client_proof {
            let hint = Vm::recursive_proof_hint(previous)
                .map_err(|e| anyhow::anyhow!("Invalid previous LCP: {e:?}"))?;
            assumptions.push(std::mem::replace(previous, hint));
        }

        Ok(PreparedLightClientCircuitInput {
            spec_id,
            circuit_input,
            assumptions,
            lcp_state_root,
            last_l2_height,
            change_set,
            last_sequencer_commitment_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use citrea_common::LightClientProverConfig;
    use citrea_primitives::risc0_cutoff::Risc0Cutoff;
    use sov_db::ledger_db::{LedgerDB, LightClientProverLedgerOps};
    use sov_db::rocks_db_config::RocksdbConfig;
    use sov_db::schema::tables::LIGHT_CLIENT_PROVER_LEDGER_TABLES;
    use sov_db::schema::types::light_client_proof::StoredLightClientProofOutput;
    use sov_mock_da::{
        MockAddress, MockBlock, MockBlockHeader, MockDaService, MockDaSpec, MockDaVerifier,
    };
    use sov_mock_zkvm::{MockCodeCommitment, MockZkGuest, MockZkvm};
    use sov_modules_api::SpecId;
    use sov_prover_storage_manager::{Config, ProverStorageManager};
    use sov_rollup_interface::da::LatestDaState;
    use sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
    use sov_rollup_interface::zk::{ProvingSessionInfo, Sp1ExecutionStats};
    use sov_rollup_interface::Network;
    use sov_state::ZkStorage;
    use tempfile::TempDir;

    use super::LightClientInputBuilder;
    use crate::circuit::initial_values::{InitialValueProvider, LCP_JMT_GENESIS_ROOT};
    use crate::circuit::LightClientProofCircuit;

    /// L0 of the synthetic cutoff.
    const L0: u64 = 10;

    /// Synthetic cutoff on an empty JMT.
    fn risc0_cutoff() -> Risc0Cutoff {
        Risc0Cutoff {
            da_state: LatestDaState {
                block_hash: MockBlockHeader::from_height(L0).hash.0,
                block_height: L0,
                ..Default::default()
            },
            l2_state_root: [3; 32],
            last_l2_height: 30,
            last_sequencer_commitment_index: 3,
            lc_state_root: LCP_JMT_GENESIS_ROOT,
        }
    }

    /// The SP1 light client prover starts with the first proof after L0 and continues with the
    /// stored proofs. It refuses the L1 blocks the RISC0 light client proved, and a missing
    /// previous proof after L0. The first input has no previous proof, and the guest accepts it
    /// with the same results as the native execution, which continued from P0 like the guest.
    #[tokio::test(flavor = "multi_thread")]
    async fn inputs_continue_from_risc0_cutoff() {
        let risc0_cutoff = risc0_cutoff();
        let tmpdir = TempDir::new().unwrap();
        let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(
            tmpdir.path(),
            None,
            Some(
                LIGHT_CLIENT_PROVER_LEDGER_TABLES
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            ),
        ))
        .unwrap();
        let storage_manager = ProverStorageManager::new(Config {
            path: tmpdir.path().join("state"),
            db_max_open_files: None,
        })
        .unwrap();
        let da_service = MockDaService::new(MockAddress::from([1; 32]), tmpdir.path());
        // The SP1 light client prover keeps the RISC0 one's initial DA height.
        let prover_config = LightClientProverConfig {
            initial_da_height: 1,
            ..Default::default()
        };
        let code_commitments = HashMap::from([(SpecId::Pomelo, MockCodeCommitment([1; 32]))]);
        let mut builder = LightClientInputBuilder::<MockDaService, MockZkvm>::new(Network::Nightly);
        builder.risc0_cutoff = Some(risc0_cutoff.clone());
        let build = |height| {
            let block = MockBlock {
                header: MockBlockHeader::from_height(height),
                is_valid: true,
                blobs: vec![],
            };
            builder.build_from_l1_block(
                &block,
                storage_manager.create_storage_for_next_l2_height(),
                &prover_config,
                &da_service,
                &ledger_db,
                &code_commitments,
            )
        };

        // The SP1 light client prover runs on the database the RISC0 light client prover left,
        // genesis initialization would not continue P0's JMT
        let error = build(L0 + 1).err().unwrap().to_string();
        assert!(
            error.contains("Missing previous light client proof for L1 block #10"),
            "{error}"
        );

        // The RISC0 light client proof at L0 is not an SP1 recursion witness
        ledger_db
            .insert_light_client_proof_data_by_l1_height(
                L0,
                b"RISC0 receipt".to_vec(),
                StoredLightClientProofOutput::from(
                    risc0_cutoff.clone().light_client_proof_output([9; 8]),
                ),
                ProvingSessionInfo::LocalExecution(Sp1ExecutionStats {
                    instruction_count: 0,
                    syscall_count: 0,
                    gas: 0,
                }),
            )
            .unwrap();

        for height in [1, L0 - 1, L0] {
            let error = build(height).err().unwrap().to_string();
            assert!(
                error.contains("is proven by the RISC0 light client"),
                "{error}"
            );
        }

        // The first SP1 proof has no previous proof and continues from P0
        let first = build(L0 + 1).unwrap();
        assert!(first.circuit_input.previous_light_client_proof.is_none());
        assert!(first.assumptions.is_empty());
        assert_eq!(first.last_l2_height, risc0_cutoff.last_l2_height);
        assert_eq!(
            first.last_sequencer_commitment_index,
            risc0_cutoff.last_sequencer_commitment_index
        );
        let sp1_light_client_proof_method_id: [u32; 8] =
            code_commitments[&SpecId::Pomelo].clone().into();
        assert_eq!(
            first.circuit_input.light_client_proof_method_id,
            sp1_light_client_proof_method_id
        );
        let network = Network::Nightly;
        let guest_output = LightClientProofCircuit::<ZkStorage, MockDaSpec, MockZkGuest>::new()
            .run_circuit(
                MockDaVerifier {},
                borsh::from_slice(&borsh::to_vec(&first.circuit_input).unwrap()).unwrap(),
                ZkStorage::new(),
                network,
                Some(risc0_cutoff.clone()),
                InitialValueProvider::<MockDaSpec>::get_l2_genesis_root(&network),
                InitialValueProvider::<MockDaSpec>::initial_batch_proof_method_ids(&network)
                    .to_vec(),
                &InitialValueProvider::<MockDaSpec>::batch_prover_da_public_key(&network),
                &InitialValueProvider::<MockDaSpec>::sequencer_da_public_key(&network),
                &InitialValueProvider::<MockDaSpec>::method_id_upgrade_authority_da_public_keys(
                    &network,
                ),
            )
            .unwrap();
        assert_eq!(
            (
                guest_output.l2_state_root,
                guest_output.lcp_state_root,
                guest_output.last_l2_height,
                guest_output.last_sequencer_commitment_index,
            ),
            (
                risc0_cutoff.l2_state_root,
                first.lcp_state_root,
                first.last_l2_height,
                first.last_sequencer_commitment_index,
            )
        );
        assert_eq!(guest_output.latest_da_state.block_height, L0 + 1);
        let error = build(L0 + 2).err().unwrap().to_string();
        assert!(
            error.contains("Missing previous light client proof"),
            "{error}"
        );

        // The next one is built on the stored first proof
        let lcp_state_root = first.lcp_state_root;
        storage_manager.finalize_storage(first.change_set);
        let first_proof = vec![1, 2, 3];
        let block_hash = MockBlockHeader::from_height(L0 + 1).hash.0;
        ledger_db
            .insert_light_client_proof_data_by_l1_height(
                L0 + 1,
                first_proof.clone(),
                StoredLightClientProofOutput::from(LightClientCircuitOutput {
                    l2_state_root: risc0_cutoff.l2_state_root,
                    light_client_proof_method_id: [1; 8],
                    latest_da_state: LatestDaState {
                        block_hash,
                        block_height: L0 + 1,
                        total_work: [0; 32],
                        current_target_bits: 0,
                        epoch_start_time: 0,
                        prev_11_timestamps: [0; 11],
                    },
                    last_l2_height: risc0_cutoff.last_l2_height,
                    lcp_state_root,
                    last_sequencer_commitment_index: risc0_cutoff.last_sequencer_commitment_index,
                }),
                ProvingSessionInfo::LocalExecution(Sp1ExecutionStats {
                    instruction_count: 0,
                    syscall_count: 0,
                    gas: 0,
                }),
            )
            .unwrap();
        let second = build(L0 + 2).unwrap();
        assert!(second.circuit_input.previous_light_client_proof.is_some());
        assert_eq!(second.assumptions, vec![first_proof]);
        assert_eq!(second.last_l2_height, risc0_cutoff.last_l2_height);
    }
}
