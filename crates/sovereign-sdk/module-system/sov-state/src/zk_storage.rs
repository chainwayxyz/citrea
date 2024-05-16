use std::marker::PhantomData;
use std::sync::Arc;

use jmt::KeyHash;
use sov_modules_core::{
    OrderedReadsAndWrites, StateDiff, Storage, StorageKey, StorageProof, StorageValue, Witness,
};
#[cfg(all(target_os = "zkvm", feature = "bench"))]
use sov_zk_cycle_macros::cycle_tracker;

use crate::MerkleProofSpec;

#[cfg(all(target_os = "zkvm", feature = "bench"))]
extern crate risc0_zkvm;

/// A [`Storage`] implementation designed to be used inside the zkVM.
#[derive(Default)]
pub struct ZkStorage<S: MerkleProofSpec> {
    _phantom_hasher: PhantomData<S::Hasher>,
}

impl<S: MerkleProofSpec> Clone for ZkStorage<S> {
    fn clone(&self) -> Self {
        Self {
            _phantom_hasher: Default::default(),
        }
    }
}

impl<S: MerkleProofSpec> ZkStorage<S> {
    /// Creates a new [`ZkStorage`] instance. Identical to [`Default::default`].
    pub fn new() -> Self {
        Self {
            _phantom_hasher: Default::default(),
        }
    }
}

impl<S: MerkleProofSpec> Storage for ZkStorage<S> {
    type Witness = S::Witness;
    type RuntimeConfig = ();
    type Proof = jmt::proof::SparseMerkleProof<S::Hasher>;
    type Root = jmt::RootHash;
    type StateUpdate = ();

    fn get(
        &self,
        _key: &StorageKey,
        _version: Option<u64>,
        witness: &Self::Witness,
    ) -> Option<StorageValue> {
        witness.get_hint()
    }

    #[cfg_attr(all(target_os = "zkvm", feature = "bench"), cycle_tracker)]
    fn compute_state_update(
        &self,
        state_accesses: OrderedReadsAndWrites,
        witness: &Self::Witness,
    ) -> Result<
        (
            Self::Root,
            Self::StateUpdate,
            Vec<(Vec<u8>, Option<Vec<u8>>)>,
        ),
        anyhow::Error,
    > {
        let prev_state_root = witness.get_hint();

        // For each value that's been read from the tree, verify the provided smt proof
        for (key, read_value) in state_accesses.ordered_reads {
            let key_hash = KeyHash::with::<S::Hasher>(key.key.as_ref());
            // TODO: Switch to the batch read API once it becomes available
            let proof: jmt::proof::SparseMerkleProof<S::Hasher> = witness.get_hint();
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
        let batch = state_accesses
            .ordered_writes
            .into_iter()
            .map(|(key, value)| {
                let key_hash = KeyHash::with::<S::Hasher>(key.key.as_ref());

                let key_bytes = Arc::try_unwrap(key.key).unwrap_or_else(|arc| (*arc).clone());
                let value_bytes =
                    value.map(|v| Arc::try_unwrap(v.value).unwrap_or_else(|arc| (*arc).clone()));

                diff.push((key_bytes, value_bytes.clone()));

                (key_hash, value_bytes)
            })
            .collect::<Vec<_>>();

        let update_proof: jmt::proof::UpdateMerkleProof<S::Hasher> = witness.get_hint();
        let new_root: [u8; 32] = witness.get_hint();
        update_proof
            .verify_update(
                jmt::RootHash(prev_state_root),
                jmt::RootHash(new_root),
                batch,
            )
            .expect("Updates must be valid");

        Ok((jmt::RootHash(new_root), (), diff))
    }

    #[cfg_attr(all(target_os = "zkvm", feature = "bench"), cycle_tracker)]
    fn commit(&self, _node_batch: &Self::StateUpdate, _accessory_writes: &OrderedReadsAndWrites) {}

    fn open_proof(
        state_root: Self::Root,
        state_proof: StorageProof<Self::Proof>,
    ) -> Result<(StorageKey, Option<StorageValue>), anyhow::Error> {
        let StorageProof { key, value, proof } = state_proof;
        let key_hash = KeyHash::with::<S::Hasher>(key.as_ref());

        proof.verify(state_root, key_hash, value.as_ref().map(|v| v.value()))?;
        Ok((key, value))
    }

    fn is_empty(&self) -> bool {
        unimplemented!("Needs simplification in JellyfishMerkleTree: https://github.com/Sovereign-Labs/sovereign-sdk/issues/362")
    }
}
