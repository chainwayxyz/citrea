use jmt::KeyHash;
use sov_modules_core::{
    OrderedWrites, ReadWriteLog, Storage, StorageKey, StorageProof, StorageValue, Witness,
};
use sov_rollup_interface::stf::{StateDiff, StateRootTransition};
use sov_rollup_interface::zk::StorageRootHash;

use crate::DefaultHasher;

/// A [`Storage`] implementation designed to be used inside the zkVM.
#[derive(Default, Clone)]
pub struct ZkStorage;

impl ZkStorage {
    /// Creates a new [`ZkStorage`] instance. Identical to [`Default::default`].
    pub fn new() -> Self {
        Self {}
    }
}

impl Storage for ZkStorage {
    type RuntimeConfig = ();
    type StateUpdate = ();

    fn get(&self, _key: &StorageKey, witness: &mut Witness) -> Option<StorageValue> {
        witness.get_hint()
    }

    fn get_offchain(&self, _key: &StorageKey, witness: &mut Witness) -> Option<StorageValue> {
        witness.get_hint()
    }

    fn compute_state_update(
        &self,
        state_log: &ReadWriteLog,
        witness: &mut Witness,
    ) -> Result<(StateRootTransition, Self::StateUpdate, StateDiff), anyhow::Error> {
        let prev_state_root = witness.get_hint();

        // For each value that's been read from the tree, verify the provided jmt proof
        for (key, read_value) in state_log.ordered_reads() {
            let key_hash = KeyHash::with::<DefaultHasher>(key.key.as_ref());
            // TODO: Switch to the batch read API once it becomes available
            let proof: jmt::proof::SparseMerkleProof<DefaultHasher> = witness.get_hint();
            match read_value {
                Some(val) => proof.verify_existence(
                    jmt::RootHash(prev_state_root),
                    key_hash,
                    val.value.as_ref(),
                )?,
                None => proof.verify_nonexistence(jmt::RootHash(prev_state_root), key_hash)?,
            }
        }

        let mut diff = vec![];

        // Compute the jmt update from the write batch
        let batch = state_log
            .iter_ordered_writes()
            .map(|(key, value)| {
                let key_hash = KeyHash::with::<DefaultHasher>(key.key.as_ref());

                let key_bytes = key.key.clone();
                let value_bytes = value.as_ref().map(|v| v.value.clone());

                // Seems like we can get rid of the extra clone here
                diff.push((key_bytes, value_bytes.clone()));

                (key_hash, value_bytes)
            })
            .collect::<Vec<_>>();

        let update_proof: jmt::proof::UpdateMerkleProof<DefaultHasher> = witness.get_hint();
        let new_root: [u8; 32] = witness.get_hint();
        update_proof
            .verify_update(
                jmt::RootHash(prev_state_root),
                jmt::RootHash(new_root),
                batch,
            )
            .expect("Updates must be valid");

        Ok((
            StateRootTransition {
                init_root: prev_state_root,
                final_root: new_root,
            },
            (),
            diff,
        ))
    }

    fn commit(
        &self,
        _node_batch: &Self::StateUpdate,
        _accessory_writes: &OrderedWrites,
        _offchain_log: &ReadWriteLog,
    ) {
    }

    fn open_proof(
        state_root: StorageRootHash,
        state_proof: StorageProof,
    ) -> Result<(StorageKey, Option<StorageValue>), anyhow::Error> {
        let StorageProof { key, value, proof } = state_proof;
        let key_hash = KeyHash::with::<DefaultHasher>(key.as_ref());

        proof.verify(
            jmt::RootHash(state_root),
            key_hash,
            value.as_ref().map(|v| v.value()),
        )?;
        Ok((key, value))
    }

    fn is_empty(&self) -> bool {
        unimplemented!("Needs simplification in JellyfishMerkleTree: https://github.com/Sovereign-Labs/sovereign-sdk/issues/362")
    }

    fn clone_with_version(&self, _version: jmt::Version) -> Self {
        unimplemented!("ZkStorage::clone_with_version should never be called")
    }
}
