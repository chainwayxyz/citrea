use sha2::Digest;
use sov_mock_da::{MockAddress, MockBlob, MockBlock, MockBlockHeader, MockDaSpec};
use sov_modules_api::default_context::DefaultContext;
use sov_modules_api::hooks::{HookSoftConfirmationInfo, SoftConfirmationError};
use sov_modules_api::transaction::Transaction;
use sov_modules_api::Context;
use sov_modules_stf_blueprint::StfBlueprintTrait;
use sov_prover_storage_manager::{new_orphan_storage, SnapshotManager};
use sov_rollup_interface::da::{BlobReaderTrait, BlockHeaderTrait, DaSpec};
use sov_rollup_interface::spec::SpecId;
use sov_rollup_interface::stf::{
    ApplySequencerCommitmentsOutput, SlotResult, SoftConfirmationReceipt, SoftConfirmationResult,
    StateTransitionFunction,
};
use sov_state::storage::{NativeStorage, StorageKey, StorageValue};
use sov_state::{ArrayWitness, OrderedReadsAndWrites, Prefix, ProverStorage, Storage};
pub type Q = SnapshotManager;

#[derive(Default, Clone)]
pub struct HashStf;

impl HashStf {
    pub fn new() -> Self {
        Self {}
    }

    fn hash_key() -> StorageKey {
        let prefix = Prefix::new(b"root".to_vec());
        StorageKey::singleton(&prefix)
    }

    fn save_from_hasher(
        hasher: sha2::Sha256,
        storage: ProverStorage<Q>,
        witness: &mut ArrayWitness,
    ) -> ([u8; 32], ProverStorage<Q>) {
        let result = hasher.finalize();

        let hash_key = HashStf::hash_key();
        let hash_value = StorageValue::from(result.as_slice().to_vec());

        let ordered_reads_writes = OrderedReadsAndWrites {
            ordered_reads: Vec::default(),
            ordered_writes: vec![(hash_key.to_cache_key(), Some(hash_value.into_cache_value()))],
        };

        let (state_root_transition, state_update, _) = storage
            .compute_state_update(ordered_reads_writes, witness)
            .unwrap();

        storage.commit(
            &state_update,
            &OrderedReadsAndWrites::default(),
            &OrderedReadsAndWrites::default(),
        );

        let mut root_hash = [0u8; 32];

        for (i, &byte) in state_root_transition
            .final_root
            .as_ref()
            .iter()
            .enumerate()
            .take(32)
        {
            root_hash[i] = byte;
        }

        (root_hash, storage)
    }
}

impl<C: Context, Da: DaSpec> StfBlueprintTrait<C, Da> for HashStf {
    fn begin_soft_confirmation(
        &mut self,
        _sequencer_public_key: &[u8],
        _pre_state: Self::PreState,
        _state_witness: <<C as sov_modules_api::Spec>::Storage as Storage>::Witness,
        _offchain_witness: <<C as sov_modules_api::Spec>::Storage as Storage>::Witness,
        _slot_header: &<Da as DaSpec>::BlockHeader,
        _soft_confirmation_info: &HookSoftConfirmationInfo,
    ) -> (
        Result<(), SoftConfirmationError>,
        sov_modules_api::WorkingSet<C>,
    ) {
        unimplemented!()
    }

    fn apply_soft_confirmation_txs(
        &mut self,
        _soft_confirmation_info: HookSoftConfirmationInfo,
        _txs: &[Vec<u8>],
        _txs_new: &[Self::Transaction],
        _batch_workspace: sov_modules_api::WorkingSet<C>,
    ) -> (
        sov_modules_api::WorkingSet<C>,
        Vec<sov_modules_stf_blueprint::TransactionReceipt<sov_modules_stf_blueprint::TxEffect>>,
    ) {
        unimplemented!()
    }

    fn end_soft_confirmation(
        &mut self,
        _current_spec: SpecId,
        _pre_state_root: Vec<u8>,
        _sequencer_public_key: &[u8],
        _soft_confirmation: &mut sov_modules_api::SignedSoftConfirmation<Self::Transaction>,
        _tx_receipts: Vec<
            sov_modules_stf_blueprint::TransactionReceipt<sov_modules_stf_blueprint::TxEffect>,
        >,
        _batch_workspace: sov_modules_api::WorkingSet<C>,
    ) -> (
        Result<
            SoftConfirmationReceipt<sov_modules_stf_blueprint::TxEffect, Da>,
            SoftConfirmationError,
        >,
        sov_modules_api::StateCheckpoint<C>,
    ) {
        unimplemented!()
    }

    fn finalize_soft_confirmation(
        &self,
        _current_spec: SpecId,
        _sc_receipt: SoftConfirmationReceipt<sov_modules_stf_blueprint::TxEffect, Da>,
        _checkpoint: sov_modules_api::StateCheckpoint<C>,
        _pre_state: Self::PreState,
        _soft_confirmation: &mut sov_modules_api::SignedSoftConfirmation<Self::Transaction>,
    ) -> SoftConfirmationResult<
        Self::StateRoot,
        Self::ChangeSet,
        Self::TxReceiptContents,
        Self::Witness,
        Da,
    > {
        unimplemented!()
    }
}

impl<Da: DaSpec> StateTransitionFunction<Da> for HashStf {
    type Transaction = Transaction<DefaultContext>;
    type StateRoot = [u8; 32];
    type GenesisParams = Vec<u8>;
    type PreState = ProverStorage<Q>;
    type ChangeSet = ProverStorage<Q>;
    type TxReceiptContents = ();
    type BatchReceiptContents = [u8; 32];
    type Witness = ArrayWitness;

    fn init_chain(
        &self,
        genesis_state: Self::PreState,
        params: Self::GenesisParams,
    ) -> (Self::StateRoot, Self::ChangeSet) {
        let mut hasher = sha2::Sha256::new();
        hasher.update(params);

        HashStf::save_from_hasher(hasher, genesis_state, &mut ArrayWitness::default())
    }

    fn apply_slot<'a, I>(
        &self,
        _current_spec: SpecId,
        pre_state_root: &Self::StateRoot,
        storage: Self::PreState,
        mut witness: Self::Witness,
        slot_header: &Da::BlockHeader,
        blobs: I,
    ) -> SlotResult<
        Self::StateRoot,
        Self::ChangeSet,
        Self::BatchReceiptContents,
        Self::TxReceiptContents,
        Self::Witness,
    >
    where
        I: IntoIterator<Item = &'a mut Da::BlobTransaction>,
    {
        tracing::debug!(
            "Applying slot in HashStf at height={}",
            slot_header.height()
        );
        let mut hasher = sha2::Sha256::new();

        let hash_key = HashStf::hash_key();
        let existing_cache = storage.get(&hash_key, None, &mut witness).unwrap();
        tracing::debug!(
            "HashStf provided_state_root={:?}, saved={:?}",
            pre_state_root,
            existing_cache.value()
        );
        hasher.update(existing_cache.value());

        for blob in blobs {
            let data = blob.verified_data();
            hasher.update(data);
        }

        let (state_root, storage) = HashStf::save_from_hasher(hasher, storage, &mut witness);

        SlotResult {
            state_root,
            change_set: storage,
            // TODO: Add batch receipts to inspection
            batch_receipts: vec![],
            witness,
            state_diff: vec![],
        }
    }

    fn apply_soft_confirmation(
        &mut self,
        _current_spec: SpecId,
        _sequencer_public_key: &[u8],
        _pre_state_root: &Self::StateRoot,
        _pre_state: Self::PreState,
        _state_witness: Self::Witness,
        _offchain_witness: Self::Witness,
        _slot_header: &<Da as DaSpec>::BlockHeader,
        _soft_confirmation: &mut sov_modules_api::SignedSoftConfirmation<Self::Transaction>,
    ) -> Result<
        SoftConfirmationResult<
            Self::StateRoot,
            Self::ChangeSet,
            Self::TxReceiptContents,
            Self::Witness,
            Da,
        >,
        SoftConfirmationError,
    > {
        todo!()
    }

    fn apply_soft_confirmations_from_sequencer_commitments(
        &mut self,
        _sequencer_public_key: &[u8],
        _sequencer_da_public_key: &[u8],
        _initial_state_root: &Self::StateRoot,
        _pre_state: Self::PreState,
        _da_data: Vec<<Da as DaSpec>::BlobTransaction>,
        _sequencer_commitments_range: (u32, u32),
        _witnesses: std::collections::VecDeque<Vec<(Self::Witness, Self::Witness)>>,
        _slot_headers: std::collections::VecDeque<Vec<<Da as DaSpec>::BlockHeader>>,
        _soft_confirmations: std::collections::VecDeque<
            Vec<sov_modules_api::SignedSoftConfirmation<Self::Transaction>>,
        >,
        _preproven_commitment_indicies: Vec<usize>,
    ) -> ApplySequencerCommitmentsOutput<Self::StateRoot> {
        todo!()
    }
}

#[test]
fn compare_output() {
    let genesis_params: Vec<u8> = vec![1, 2, 3, 4, 5];

    let raw_blobs: Vec<Vec<Vec<u8>>> = vec![
        // Block A
        vec![vec![1, 1, 1], vec![2, 2, 2]],
        // Block B
        vec![vec![3, 3, 3], vec![4, 4, 4], vec![5, 5, 5]],
        // Block C
        vec![vec![6, 6, 6]],
        // Block D
        vec![vec![7, 7, 7], vec![8, 8, 8]],
    ];

    let mut blocks = Vec::new();

    for (idx, raw_block) in raw_blobs.iter().enumerate() {
        let mut blobs = Vec::new();
        for raw_blob in raw_block.iter() {
            let blob = MockBlob::new(
                raw_blob.clone(),
                MockAddress::new([11u8; 32]),
                [idx as u8; 32],
            );
            blobs.push(blob);
        }

        let block = MockBlock {
            header: MockBlockHeader::from_height((idx + 1) as u64),
            is_valid: true,
            blobs,
        };
        blocks.push(block);
    }

    let (state_root, root_hash) = get_result_from_blocks(&genesis_params, &blocks);

    assert!(root_hash.is_some());

    let recorded_state_root: [u8; 32] = [
        121, 110, 56, 75, 48, 251, 66, 243, 236, 155, 4, 128, 238, 122, 188, 160, 17, 46, 169, 39,
        160, 142, 220, 208, 15, 213, 221, 250, 108, 52, 7, 46,
    ];

    assert_eq!(recorded_state_root, state_root);
}

// Returns final data hash and root hash
pub fn get_result_from_blocks(
    genesis_params: &[u8],
    blocks: &[MockBlock],
) -> ([u8; 32], Option<<ProverStorage<Q> as Storage>::Root>) {
    let tmpdir = tempfile::tempdir().unwrap();

    let storage = new_orphan_storage(tmpdir.path()).unwrap();

    let stf = HashStf::new();

    let (genesis_state_root, mut storage) =
        <HashStf as StateTransitionFunction<MockDaSpec>>::init_chain(
            &stf,
            storage,
            genesis_params.to_vec(),
        );

    let mut state_root = genesis_state_root;

    let l = blocks.len();

    for block in blocks {
        let mut blobs = block.blobs.clone();

        let result =
            <HashStf as StateTransitionFunction<MockDaSpec>>::apply_slot::<&mut Vec<MockBlob>>(
                &stf,
                SpecId::Genesis,
                &state_root,
                storage,
                ArrayWitness::default(),
                &block.header,
                &mut blobs,
            );

        state_root = result.state_root;
        storage = result.change_set;
    }

    let root_hash = storage.get_root_hash(l as u64).ok();
    (state_root, root_hash)
}
