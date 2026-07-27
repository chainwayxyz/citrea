//! Shared light client circuit input construction.

use std::collections::HashMap;

use citrea_common::LightClientProverConfig;
use citrea_primitives::forks::fork_from_block_number;
use sov_db::ledger_db::LightClientProverLedgerOps;
use sov_modules_api::{SpecId, Zkvm};
use sov_prover_storage_manager::ProverStorage;
use sov_rollup_interface::da::{BlockHeaderTrait, DaSpec};
use sov_rollup_interface::services::da::{DaService, SlotData};
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use sov_rollup_interface::Network;

use crate::circuit::initial_values::InitialValueProvider;
use crate::circuit::{LightClientProofCircuit, RunL1BlockResult};

/// Prepared light client circuit input and native state transition data.
pub(crate) struct PreparedLightClientCircuitInput<DS: DaSpec> {
    /// Spec ID used to select the light client proof circuit.
    pub(crate) spec_id: SpecId,
    /// Borsh-serializable input that can be passed to the light client circuit.
    pub(crate) circuit_input: LightClientCircuitInput<DS>,
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
    /// Native light client circuit runner used to produce witness data.
    pub(crate) circuit: LightClientProofCircuit<ProverStorage, Da::Spec, Vm>,
}

impl<Da, Vm> LightClientInputBuilder<Da, Vm>
where
    Da: DaService,
    Vm: Zkvm,
    Network: InitialValueProvider<Da::Spec>,
{
    /// Creates a builder for the given network with a reusable native circuit runner.
    pub(crate) fn new(network: Network) -> Self {
        Self {
            network,
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

        let previous_l1_height = l1_height.saturating_sub(1);
        let (previous_lcp_proof, l2_last_height, previous_lcp_output) = match ledger_db
            .get_light_client_proof_data_by_l1_height(previous_l1_height)?
        {
            Some(data) => {
                let output = LightClientCircuitOutput::from(data.light_client_proof_output);
                (Some(data.proof), output.last_l2_height, Some(output))
            }
            None if l1_height == prover_config.initial_da_height => {
                // first time proving a light client proof
                tracing::warn!(
                    "Creating initial light client proof on L1 block #{}",
                    l1_height
                );
                (None, 0, None)
            }
            None => {
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

        let current_fork = fork_from_block_number(l2_last_height);
        let light_client_proof_code_commitment = code_commitments
            .get(&current_fork.spec_id)
            .ok_or_else(|| anyhow::anyhow!("Fork should have a guest code attached"))?;

        let circuit_input = LightClientCircuitInput {
            inclusion_proof,
            completeness_proof,
            da_block_header: l1_block.header().clone(),
            light_client_proof_method_id: light_client_proof_code_commitment.clone().into(),
            previous_light_client_proof: previous_lcp_proof,
            witness,
        };

        Ok(PreparedLightClientCircuitInput {
            spec_id: current_fork.spec_id,
            circuit_input,
            lcp_state_root,
            last_l2_height,
            change_set,
            last_sequencer_commitment_index,
        })
    }
}
