use std::marker::PhantomData;
use std::sync::Arc;

use jmt::KeyHash;
use sha2::Digest;
use sov_modules_core::{
    OrderedReadsAndWrites, Storage, StorageKey, StorageProof, StorageValue, Witness,
};
use sov_rollup_interface::stf::StateDiff;
#[cfg(all(target_os = "zkvm", feature = "bench"))]
use sov_zk_cycle_macros::cycle_tracker;

#[cfg(all(target_os = "zkvm", feature = "bench"))]
extern crate risc0_zkvm;

/// A [`Storage`] implementation designed to be used inside the zkVM.
#[derive(Default)]
pub struct ZkStorage<W, H>
where
    W: Witness + Send + Sync,
    H: Digest<OutputSize = sha2::digest::typenum::U32>,
{
    _phantom_hasher: PhantomData<(W, H)>,
}

impl<W, H> Clone for ZkStorage<W, H>
where
    W: Witness + Send + Sync,
    H: Digest<OutputSize = sha2::digest::typenum::U32>,
{
    fn clone(&self) -> Self {
        Self {
            _phantom_hasher: Default::default(),
        }
    }
}

impl<W, H> ZkStorage<W, H>
where
    W: Witness + Send + Sync,
    H: Digest<OutputSize = sha2::digest::typenum::U32>,
{
    /// Creates a new [`ZkStorage`] instance. Identical to [`Default::default`].
    pub fn new() -> Self {
        Self {
            _phantom_hasher: Default::default(),
        }
    }
}

impl<W, H> Storage for ZkStorage<W, H>
where
    W: Witness + Send + Sync,
    H: Digest<OutputSize = sha2::digest::typenum::U32>,
{
    type Witness = W;
    type RuntimeConfig = ();
    type Proof = jmt::proof::SparseMerkleProof<H>;
    type Root = jmt::RootHash;
    type StateUpdate = ();

    fn get(
        &self,
        _key: &StorageKey,
        _version: Option<u64>,
        witness: &mut Self::Witness,
    ) -> Option<StorageValue> {
        witness.get_hint()
    }

    #[cfg_attr(all(target_os = "zkvm", feature = "bench"), cycle_tracker)]
    fn compute_state_update(
        &self,
        state_accesses: OrderedReadsAndWrites,
        witness: &mut Self::Witness,
    ) -> Result<(Self::Root, Self::StateUpdate, StateDiff), anyhow::Error> {
        let prev_state_root = witness.get_hint();

        // For each value that's been read from the tree, verify the provided smt proof
        for (key, read_value) in state_accesses.ordered_reads {
            let key_hash = KeyHash::with::<H>(key.key.as_ref());
            // TODO: Switch to the batch read API once it becomes available
            let proof: jmt::proof::SparseMerkleProof<H> = witness.get_hint();
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
                let key_hash = KeyHash::with::<H>(key.key.as_ref());

                let key_bytes = Arc::try_unwrap(key.key).unwrap_or_else(|arc| (*arc).clone());
                let value_bytes =
                    value.map(|v| Arc::try_unwrap(v.value).unwrap_or_else(|arc| (*arc).clone()));

                diff.push((key_bytes, value_bytes.clone()));

                (key_hash, value_bytes)
            })
            .collect::<Vec<_>>();

        let update_proof: jmt::proof::UpdateMerkleProof<H> = witness.get_hint();
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
        let key_hash = KeyHash::with::<H>(key.as_ref());

        proof.verify(state_root, key_hash, value.as_ref().map(|v| v.value()))?;
        Ok((key, value))
    }

    fn is_empty(&self) -> bool {
        unimplemented!("Needs simplification in JellyfishMerkleTree: https://github.com/Sovereign-Labs/sovereign-sdk/issues/362")
    }
}
