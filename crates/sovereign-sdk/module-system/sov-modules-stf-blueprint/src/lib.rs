#![deny(missing_docs)]
#![doc = include_str!("../README.md")]

use borsh::BorshDeserialize;
use citrea_primitives::EMPTY_TX_ROOT;
use rs_merkle::algorithms::Sha256;
use rs_merkle::MerkleTree;
use sov_keys::default_signature::{K256PublicKey, K256Signature};
use sov_keys::Signature;
use sov_modules_api::fork::Fork;
use sov_modules_api::hooks::{
    ApplyL2BlockHooks, FinalizeHook, HookL2BlockInfo, SlotHooks, TxHooks,
};
use sov_modules_api::{native_debug, Context, DaSpec, DispatchCall, Genesis, Spec, WorkingSet};
use sov_rollup_interface::block::{L2Block, SignedL2Header};
use sov_rollup_interface::da::SequencerCommitment;
use sov_rollup_interface::fork::ForkManager;
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::{L2BlockError, L2BlockResult, StateTransitionError};
use sov_rollup_interface::transaction::Transaction;
use sov_rollup_interface::zk::batch_proof::output::CumulativeStateDiff;
use sov_rollup_interface::zk::{StorageRootHash, ZkvmGuest};
use sov_state::{ReadWriteLog, Storage, Witness};

mod stf_blueprint;

pub use stf_blueprint::StfBlueprint;

/// The tx hook for a blueprint runtime
pub struct RuntimeTxHook {
    /// Height to initialize the context
    pub height: u64,
    /// Current spec
    pub current_spec: SpecId,
    /// L1 fee rate
    pub l1_fee_rate: u128,
}

/// This trait has to be implemented by a runtime in order to be used in `StfBlueprint`.
///
/// The `TxHooks` implementation sets up a transaction context based on the height at which it is
/// to be executed.
pub trait Runtime<C: Context, Da: DaSpec>:
    DispatchCall<Context = C>
    + Genesis<Context = C, Config = Self::GenesisConfig>
    + TxHooks<Context = C, PreArg = RuntimeTxHook, PreResult = C>
    + SlotHooks<Da, Context = C>
    + FinalizeHook<Da, Context = C>
    + ApplyL2BlockHooks<Da, Context = C>
    + Default
{
    /// GenesisConfig type.
    type GenesisConfig: Send + Sync;

    #[cfg(feature = "native")]
    /// GenesisPaths type.
    type GenesisPaths: Send + Sync;

    #[cfg(feature = "native")]
    /// Default rpc methods.
    fn rpc_methods(storage: C::Storage) -> jsonrpsee::RpcModule<()>;

    #[cfg(feature = "native")]
    /// Reads genesis configs.
    fn genesis_config(
        genesis_paths: &Self::GenesisPaths,
    ) -> Result<Self::GenesisConfig, anyhow::Error>;
}

/// Genesis parameters for a blueprint
pub struct GenesisParams<RT> {
    /// The runtime genesis parameters
    pub runtime: RT,
}

/// The output of the function that applies sequencer commitments to the state in the verifier
pub struct ApplySequencerCommitmentsOutput {
    /// All of the state roots of commitments from initial state (previous commitments state root) to the last sequencer commitment
    pub state_roots: Vec<StorageRootHash>,
    /// State diff generated after applying
    pub state_diff: CumulativeStateDiff,
    /// Last processed L2 block height
    pub last_l2_height: u64,
    /// Last l2 block hash
    pub final_l2_block_hash: [u8; 32],
    /// Sequencer commitment hashes
    pub sequencer_commitment_hashes: Vec<[u8; 32]>,
    /// The range of sequencer commitments that were processed.
    pub sequencer_commitment_index_range: (u32, u32),
    /// Cumulative state log
    pub cumulative_state_log: ReadWriteLog,
    /// The index of the previous commitment that was given as input in the batch proof
    pub previous_commitment_index: Option<u32>,
    /// The hash of the previous commitment that was given as input in the batch proof
    pub previous_commitment_hash: Option<[u8; 32]>,
}

impl<C, RT, Da> StfBlueprint<C, Da, RT>
where
    C: Context,
    Da: DaSpec,
    RT: Runtime<C, Da>,
{
    /// Begin a l2 block for blocks post tangerine
    /// There are no slot hash comparisons with l2 blocks
    pub fn begin_l2_block(
        &mut self,
        sequencer_public_key: &K256PublicKey,
        working_set: &mut WorkingSet<C::Storage>,
        l2_block_info: &HookL2BlockInfo,
    ) -> Result<(), StateTransitionError> {
        // check if l2 block is coming from our sequencer
        if l2_block_info.sequencer_pub_key() != sequencer_public_key {
            return Err(StateTransitionError::L2BlockError(
                L2BlockError::SequencerPublicKeyMismatch,
            ));
        };

        self.begin_l2_block_inner(working_set, l2_block_info)
            .map_err(StateTransitionError::HookError)
    }

    /// Apply l2 block transactions
    pub fn apply_l2_block_txs(
        &mut self,
        l2_block_info: &HookL2BlockInfo,
        txs: &[Transaction],
        batch_workspace: &mut WorkingSet<C::Storage>,
    ) -> Result<(), StateTransitionError> {
        self.apply_sov_txs_inner(l2_block_info, txs, batch_workspace)
    }

    /// Verify l2_block hash and signature post tangerine
    /// No da slot hash, height and txs commitment checks are done here
    pub fn verify_l2_block(
        &self,
        l2_block: &L2Block,
        sequencer_public_key: &K256PublicKey,
    ) -> Result<(), StateTransitionError> {
        let l2_header = &l2_block.header;

        verify_tx_merkle_root::<C>(l2_block)
            .map_err(|_| StateTransitionError::L2BlockError(L2BlockError::InvalidTxMerkleRoot))?;

        let expected_hash =
            Into::<[u8; 32]>::into(l2_header.inner.compute_digest::<<C as Spec>::Hasher>());

        if l2_block.hash() != expected_hash {
            return Err(StateTransitionError::L2BlockError(
                L2BlockError::InvalidL2BlockHash,
            ));
        }

        verify_signature(l2_header, sequencer_public_key)
            .map_err(|_| StateTransitionError::L2BlockError(L2BlockError::InvalidL2BlockSignature))
    }

    /// End a l2 block
    pub fn end_l2_block(
        &mut self,
        l2_block_info: HookL2BlockInfo,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Result<(), StateTransitionError> {
        self.end_l2_block_inner(l2_block_info, working_set)
            .map_err(StateTransitionError::HookError)
    }

    /// Finalizes a l2 block
    pub fn finalize_l2_block(
        &self,
        _current_spec: SpecId,
        working_set: WorkingSet<C::Storage>,
        pre_state: C::Storage,
    ) -> L2BlockResult<C::Storage, Witness, ReadWriteLog> {
        let (
            state_root_transition,
            state_log,
            offchain_log,
            witness,
            offchain_witness,
            storage,
            state_diff,
        ) = {
            // Save checkpoint
            let mut checkpoint = working_set.checkpoint();

            let (state_log, mut witness) = checkpoint.freeze();

            let (state_root_transition, state_update, state_diff) = pre_state
                .compute_state_update(&state_log, &mut witness, true)
                .expect("jellyfish merkle tree update must succeed");

            let mut working_set = checkpoint.to_revertable();

            self.runtime.finalize_hook(
                &state_root_transition.final_root,
                &mut working_set.accessory_state(),
            );

            let mut checkpoint = working_set.checkpoint();
            let accessory_log = checkpoint.freeze_non_provable();
            let (offchain_log, offchain_witness) = checkpoint.freeze_offchain();

            pre_state.commit(&state_update, &accessory_log, &offchain_log);

            (
                state_root_transition,
                state_log,
                offchain_log,
                witness,
                offchain_witness,
                pre_state,
                state_diff,
            )
        };

        L2BlockResult {
            state_root_transition,
            state_log,
            offchain_log,
            change_set: storage,
            witness,
            offchain_witness,
            state_diff,
        }
    }
}

impl<C, RT, Da> StfBlueprint<C, Da, RT>
where
    C: Context,
    Da: DaSpec,
    RT: Runtime<C, Da>,
{
    /// Initialize chain from genesis config
    pub fn init_chain(
        &self,
        pre_state: C::Storage,
        params: GenesisParams<<RT as Genesis>::Config>,
    ) -> (StorageRootHash, C::Storage) {
        let mut working_set = WorkingSet::new(pre_state.clone());

        self.runtime.genesis(&params.runtime, &mut working_set);

        let mut checkpoint = working_set.checkpoint();
        let (state_log, mut witness) = checkpoint.freeze();

        let (state_root_transition, state_update, _) = pre_state
            .compute_state_update(&state_log, &mut witness, true)
            .expect("Storage update must succeed");
        let genesis_hash = state_root_transition.final_root;

        let mut working_set = checkpoint.to_revertable();

        self.runtime
            .finalize_hook(&genesis_hash, &mut working_set.accessory_state());

        let mut checkpoint = working_set.checkpoint();
        let accessory_log = checkpoint.freeze_non_provable();
        let (offchain_log, _offchain_witness) = checkpoint.freeze_offchain();

        pre_state.commit(&state_update, &accessory_log, &offchain_log);

        (genesis_hash, pre_state)
    }

    /// Apply l2 block
    #[allow(clippy::too_many_arguments)]
    pub fn apply_l2_block(
        &mut self,
        current_spec: SpecId,
        sequencer_public_key: &K256PublicKey,
        pre_state_root: &StorageRootHash,
        pre_state: C::Storage,
        cumulative_state_log: Option<ReadWriteLog>,
        cumulative_offchain_log: Option<ReadWriteLog>,
        state_witness: Witness,
        offchain_witness: Witness,
        l2_block: &L2Block,
    ) -> Result<L2BlockResult<C::Storage, Witness, ReadWriteLog>, StateTransitionError> {
        let l2_block_info = HookL2BlockInfo::new(
            l2_block,
            *pre_state_root,
            current_spec,
            sequencer_public_key.clone(),
        );

        let mut working_set = if let Some(state_log) = cumulative_state_log {
            WorkingSet::with_witness_and_log(
                pre_state.clone(),
                state_witness,
                offchain_witness,
                state_log,
                cumulative_offchain_log.expect("Both logs must be provided"),
            )
        } else {
            WorkingSet::with_witness(pre_state.clone(), state_witness, offchain_witness)
        };

        native_debug!("Applying l2 block in STF Blueprint");

        self.verify_l2_block(l2_block, sequencer_public_key)?;

        self.begin_l2_block(sequencer_public_key, &mut working_set, &l2_block_info)?;

        self.apply_l2_block_txs(&l2_block_info, &l2_block.txs, &mut working_set)?;

        self.end_l2_block(l2_block_info, &mut working_set)?;

        let res = self.finalize_l2_block(current_spec, working_set, pre_state);

        native_debug!(
            "l2 block with hash: {:?} has been successfully applied",
            hex::encode(l2_block.hash()),
        );

        Ok(res)
    }

    /// Apply l2 block from sequencer commitments
    #[allow(clippy::too_many_arguments)]
    pub fn apply_l2_blocks_from_sequencer_commitments(
        &mut self,
        guest: &impl ZkvmGuest,
        sequencer_public_key: &[u8],
        initial_state_root: &StorageRootHash,
        pre_state: C::Storage,
        previous_sequencer_commitment: Option<SequencerCommitment>,
        sequencer_commitments: Vec<SequencerCommitment>,
        cache_prune_l2_heights: &[u64],
        forks: &[Fork],
    ) -> ApplySequencerCommitmentsOutput {
        let sequencer_public_key = K256PublicKey::try_from_slice(sequencer_public_key)
            .expect("Sequencer public key must be valid");

        let mut state_diff = CumulativeStateDiff::default();

        let sequencer_commitment_hashes = sequencer_commitments
            .iter()
            .map(|c| c.serialize_and_calculate_sha_256())
            .collect::<Vec<_>>();

        let sequencer_commitment_index_range = (
            sequencer_commitments.first().unwrap().index,
            sequencer_commitments.last().unwrap().index,
        );

        // Verify these soft confirmations.
        let mut current_state_root = *initial_state_root;
        let mut prev_l2_block_hash: Option<[u8; 32]> = None;

        let group_count: u32 = guest.read_from_host();

        assert_eq!(group_count, sequencer_commitments.len() as u32);

        // Get tangerine
        let tangerine = forks
            .iter()
            .find(|f| f.spec_id == SpecId::Tangerine)
            .expect("Tangerine must exist");

        let tangerine_activation_height = tangerine.activation_height;

        let mut previous_batch_proof_l2_end_height = tangerine_activation_height;

        // If tangerine start height is not 0 meaning there are other forks before tangerine,
        // then the previous batch proof l2 end height should be the tangerine start height - 1
        // Because the first l2 height of the first tangerine batch proof must be non-zero tangerine activation height
        if tangerine_activation_height != 0 {
            previous_batch_proof_l2_end_height = tangerine_activation_height - 1;
        }

        // If there is no previous commitment, then this is the first batch proof
        // and this should start from proving the first l2 block
        let (previous_commitment_index, previous_commitment_hash) =
            if let Some(previous_sequencer_commitment) = previous_sequencer_commitment {
                // The index of the previous commitment should be one less than the first commitment
                assert_eq!(
                    previous_sequencer_commitment.index + 1,
                    sequencer_commitments[0].index,
                    "Sequencer commitments must be sequential"
                );
                // If there exists a previous commitment, then the first l2 block to prove
                // should be the one after the last commitment
                previous_batch_proof_l2_end_height =
                    previous_sequencer_commitment.l2_end_block_number;
                (
                    Some(previous_sequencer_commitment.index),
                    Some(previous_sequencer_commitment.serialize_and_calculate_sha_256()),
                )
            } else {
                // If this is the first batch proof, then the first commitment idx should be 1
                assert_eq!(
                    sequencer_commitments[0].index, 1,
                    "First commitment must be index 1"
                );
                (None, None)
            };
        let current_batch_proof_first_l2_height = previous_batch_proof_l2_end_height + 1;
        let mut fork_manager = ForkManager::new(forks, current_batch_proof_first_l2_height);
        let mut sequencer_commitment_l2_start_height = current_batch_proof_first_l2_height;

        let mut last_commitment_end_height = previous_batch_proof_l2_end_height;

        // Reuseable log caches
        let mut cumulative_state_log = None;
        let mut cumulative_offchain_log = None;
        let mut cache_prune_l2_heights_iter = cache_prune_l2_heights.iter().peekable();

        // State roots are pushed to this vector at the end of each sequencer commitment applied
        let mut state_roots = Vec::with_capacity(sequencer_commitments.len() + 1);
        state_roots.push(*initial_state_root);

        for sequencer_commitment in sequencer_commitments.into_iter() {
            // if the commitment is not sequential, then the proof is invalid.

            assert_eq!(
                last_commitment_end_height + 1,
                sequencer_commitment_l2_start_height,
                "Sequencer commitments must be sequential"
            );

            last_commitment_end_height = sequencer_commitment.l2_end_block_number;

            // we must verify given DA headers match the commitments

            let mut l2_height = sequencer_commitment_l2_start_height;

            let state_change_count: u32 = guest.read_from_host();
            let mut l2_block_hashes = Vec::with_capacity(state_change_count as usize);

            for _ in 0..state_change_count {
                // there used to be a need for height to be passed before L2 block
                // now this is not needed but deployed provers still have the same input generation in place
                // so don't use this variable
                let _l2_block_l2_height = guest.read_from_host::<u64>();

                let (l2_block, state_witness, offchain_witness) =
                    guest.read_from_host::<(L2Block, Witness, Witness)>();

                assert_eq!(
                    l2_block.height(),
                    l2_height,
                    "L2 block height is not equal to the expected height"
                );

                if let Some(hash) = prev_l2_block_hash {
                    assert_eq!(
                        l2_block.prev_hash(),
                        hash,
                        "L2 block previous hash must match the hash of the block before"
                    );
                }

                fork_manager.register_block(l2_height).unwrap();

                let result = self
                    .apply_l2_block(
                        fork_manager.active_fork().spec_id,
                        &sequencer_public_key,
                        &current_state_root,
                        pre_state.clone(),
                        cumulative_state_log,
                        cumulative_offchain_log,
                        state_witness,
                        offchain_witness,
                        &l2_block,
                    )
                    // TODO: this can be just ignoring the failing seq. com.
                    // We can count a failed l2 block as a valid state transition.
                    // for now we don't allow "broken" seq. com.s
                    .expect("L2 block must succeed");

                assert_eq!(current_state_root, result.state_root_transition.init_root);
                current_state_root = result.state_root_transition.final_root;
                state_diff.extend(result.state_diff);

                // The state root of prover should match l2 block coming from sequencer
                assert_eq!(current_state_root, l2_block.state_root());

                l2_height += 1;

                prev_l2_block_hash = Some(l2_block.hash());

                l2_block_hashes.push(l2_block.hash());

                let mut state_log = result.state_log;
                let mut offchain_log = result.offchain_log;
                // prune cache logs if it is hinted from native
                if cache_prune_l2_heights_iter
                    .next_if_eq(&&l2_height)
                    .is_some()
                {
                    state_log.prune_half();
                    offchain_log.prune_half();
                }

                cumulative_state_log = Some(state_log);
                cumulative_offchain_log = Some(offchain_log);
            }

            // now verify the claimed merkle root of l2 block hashes
            let calculated_root =
                MerkleTree::<Sha256>::from_leaves(l2_block_hashes.as_slice()).root();

            assert_eq!(
                calculated_root,
                Some(sequencer_commitment.merkle_root),
                "Invalid merkle root"
            );

            assert_eq!(sequencer_commitment.l2_end_block_number, l2_height - 1);
            // Update next sequencer commitment start height
            sequencer_commitment_l2_start_height = l2_height;

            state_roots.push(current_state_root);
        }

        ApplySequencerCommitmentsOutput {
            state_roots,
            state_diff,
            // There has to be a height
            last_l2_height: last_commitment_end_height,
            final_l2_block_hash: prev_l2_block_hash.unwrap(),
            sequencer_commitment_hashes,
            sequencer_commitment_index_range,
            cumulative_state_log: cumulative_state_log.unwrap(),
            previous_commitment_index,
            previous_commitment_hash,
        }
    }
}

fn verify_signature(
    header: &SignedL2Header,
    sequencer_public_key: &K256PublicKey,
) -> Result<(), anyhow::Error> {
    let signature = K256Signature::try_from(header.signature.as_slice())?;

    signature.verify(sequencer_public_key, &header.hash)?;

    Ok(())
}

fn verify_tx_merkle_root<C: Context + Spec>(
    l2_block: &L2Block,
) -> Result<(), StateTransitionError> {
    let tx_hashes: Vec<[u8; 32]> = l2_block
        .txs
        .iter()
        .map(|tx| tx.compute_digest::<<C as Spec>::Hasher>().into())
        .collect();

    let tx_merkle_root = if tx_hashes.is_empty() {
        EMPTY_TX_ROOT
    } else {
        MerkleTree::<Sha256>::from_leaves(&tx_hashes)
            .root()
            .expect("Couldn't compute merkle root")
    };

    if tx_merkle_root != l2_block.tx_merkle_root() {
        return Err(StateTransitionError::L2BlockError(
            L2BlockError::InvalidTxMerkleRoot,
        ));
    }
    Ok(())
}
