use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::{DaSpec, StateReaderAndWriter, WorkingSet, Zkvm};
use sov_modules_core::{ReadWriteLog, Storage};
use sov_rollup_interface::da::{DaNamespace, DaVerifier};
use sov_rollup_interface::witness::Witness;
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::{
    BatchProofInfo, LightClientCircuitOutput,
};
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;

use super::accessors::BlockHashAccessor;
use super::old::LightClientVerificationError;
use super::InitialBatchProofMethodIds;

struct RunL1BlockResult {
    l2_state_root: [u8; 32],
    lcp_state_root: [u8; 32],
    unchained_batch_proofs_info: Vec<BatchProofInfo>,
    last_l2_height: u64,
    batch_proof_method_ids: Vec<(u64, [u32; 8])>,
    witness: Witness,
}

struct LightClientProofCircuit<S: Storage, DaV: DaVerifier> {
    phantom: core::marker::PhantomData<(S, DaV)>,
}

impl<S: Storage, DaV: DaVerifier> LightClientProofCircuit<S, DaV> {
    // will be called by the circuit and native
    fn run_l1_block<Z: Zkvm>(
        storage: S,
        witness: Witness,
        l1_block_hash: <DaV::Spec as DaSpec>::SlotHash,
        da_txs: Vec<<DaV::Spec as DaSpec>::BlobTransaction>,
    ) -> RunL1BlockResult {
        let mut working_set =
            WorkingSet::with_witness(storage.clone(), witness, Default::default());

        // first insert the block hash into the JMT
        BlockHashAccessor::<S>::insert(l1_block_hash.into(), &mut working_set);

        let (read_write_log, mut witness) = working_set.checkpoint().freeze();

        // TODO: compute_state_update cretes state diff
        // which we don't need in this circuit
        // maybe create new function or pass argument for state diff building
        let (lcp_state_root_transition, jmt_state_update, _) = storage
            .compute_state_update(&read_write_log, &mut witness)
            .expect("jellyfish merkle tree update must succeed");

        storage.commit(&jmt_state_update, &vec![], &ReadWriteLog::default());

        RunL1BlockResult {
            l2_state_root: todo!(),
            lcp_state_root: lcp_state_root_transition.final_root,
            unchained_batch_proofs_info: todo!(),
            last_l2_height: todo!(),
            batch_proof_method_ids: todo!(),
            witness,
        }
    }

    // will only called by the circuit
    fn run_circuit<G: ZkvmGuest + Zkvm>(
        da_verifier: DaV,
        input: LightClientCircuitInput<DaV::Spec>,
        l2_genesis_root: [u8; 32],
        initial_batch_proof_method_ids: InitialBatchProofMethodIds,
        batch_prover_da_public_key: &[u8],
        method_id_upgrade_authority_da_public_key: &[u8],
        network: Network,
        storage: S,
        witness: Witness,
    ) -> Result<LightClientCircuitOutput, LightClientVerificationError<DaV>> {
        // from input, parse previous light client proof output
        let previous_light_client_proof_output = if let Some(journal) =
            input.previous_light_client_proof_journal
        {
            let prev_output = G::verify_and_deserialize_output::<LightClientCircuitOutput>(
                &journal,
                &input.light_client_proof_method_id.into(),
            )
            .map_err(|_| LightClientVerificationError::<DaV>::InvalidPreviousLightClientProof)?;
            // Ensure method IDs match
            assert_eq!(
                input.light_client_proof_method_id,
                prev_output.light_client_proof_method_id,
            );
            Some(prev_output)
        } else {
            None
        };

        // make header chain verification and insert block hash to JMT
        let new_da_state = da_verifier
            .verify_header_chain(
                previous_light_client_proof_output
                    .as_ref()
                    .map(|output| &output.latest_da_state),
                &input.da_block_header,
                network,
            )
            .map_err(|err| LightClientVerificationError::HeaderChainVerificationFailed(err))?;

        // extract DA transactions from the block
        let da_txs = da_verifier
            .verify_transactions(
                &input.da_block_header,
                input.inclusion_proof,
                input.completeness_proof,
                DaNamespace::ToLightClientProver,
            )
            .map_err(|err| LightClientVerificationError::DaTxsCouldntBeVerified(err))?;

        // then we can call run_l1_block to run the logic of the circuit
        let result =
            Self::run_l1_block::<G>(storage, witness, input.da_block_header.hash(), da_txs);

        Ok(LightClientCircuitOutput {
            state_root: result.lcp_state_root,
            light_client_proof_method_id: input.light_client_proof_method_id,
            latest_da_state: new_da_state,
            unchained_batch_proofs_info: result.unchained_batch_proofs_info,
            last_l2_height: result.last_l2_height,
            batch_proof_method_ids: result.batch_proof_method_ids,
            mmr_guest: todo!("will be removed"),
        })
    }
}
