use sov_modules_api::da::BlockHeaderTrait;
use sov_modules_api::{DaSpec, StateReaderAndWriter, WorkingSet};
use sov_modules_core::Storage;
use sov_rollup_interface::da::{DaNamespace, DaVerifier};
use sov_rollup_interface::witness::Witness;
use sov_rollup_interface::zk::light_client_proof::input::LightClientCircuitInput;
use sov_rollup_interface::zk::light_client_proof::output::LightClientCircuitOutput;
use sov_rollup_interface::zk::ZkvmGuest;
use sov_rollup_interface::Network;

use super::old::LightClientVerificationError;
use super::InitialBatchProofMethodIds;

struct LightClientProofCircuit<S: Storage, DaV: DaVerifier> {
    phantom: core::marker::PhantomData<(S, DaV)>,
}

impl<S: Storage, DaV: DaVerifier> LightClientProofCircuit<S, DaV> {
    // will be called by the circuit and native
    fn run_l1_block(storage: S, witness: Witness, l1_block_hash: <DaV::Spec as DaSpec>::SlotHash) {
        let working_set = WorkingSet::with_witness(storage, witness, Default::default());
    }

    // will only called by the circuit
    fn run_circuit<G: ZkvmGuest>(
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
        Self::run_l1_block(storage, witness, input.da_block_header.hash());

        // then we get updates and commit to storage

        todo!()
    }
}
