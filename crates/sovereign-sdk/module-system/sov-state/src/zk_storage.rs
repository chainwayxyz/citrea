use jmt::KeyHash;
use sov_modules_core::{OrderedWrites, ReadWriteLog, Storage, StorageKey, StorageValue};
use sov_rollup_interface::stateful_statediff::{self, StatefulStateDiff};
use sov_rollup_interface::stf::{StateDiff, StateRootTransition};
use sov_rollup_interface::witness::Witness;
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

    fn get_and_prove(
        &self,
        key: &StorageKey,
        witness: &mut Witness,
        state_root: StorageRootHash,
    ) -> Option<StorageValue> {
        let val: Option<StorageValue> = witness.get_hint();
        let proof: jmt::proof::SparseMerkleProof<DefaultHasher> = witness.get_hint();

        let key_hash = KeyHash::with::<DefaultHasher>(key.as_ref());
        proof
            .verify(
                jmt::RootHash(state_root),
                key_hash,
                val.as_ref().map(|val| val.value()),
            )
            .expect("JMT proof verification failed");

        val
    }

    fn get_offchain(&self, _key: &StorageKey, witness: &mut Witness) -> Option<StorageValue> {
        witness.get_hint()
    }

    fn compute_state_update(
        &self,
        state_log: &ReadWriteLog,
        witness: &mut Witness,
    ) -> Result<
        (
            StateRootTransition,
            Self::StateUpdate,
            (StateDiff, StatefulStateDiff),
        ),
        anyhow::Error,
    > {
        let prev_state_root = witness.get_hint();

        // For each value that's been read from the tree, verify the provided jmt proof
        for (key, read_value) in state_log.ordered_reads() {
            let key_hash = KeyHash::with::<DefaultHasher>(key.key.as_ref());
            // TODO: Switch to the batch read API once it becomes available
            let proof: jmt::proof::SparseMerkleProof<DefaultHasher> = witness.get_hint();
            let value = read_value.as_ref().map(|val| val.value.as_ref());
            proof.verify(jmt::RootHash(prev_state_root), key_hash, value)?;
        }

        let pre_state =
            stateful_statediff::build_pre_state(state_log.ordered_reads().iter().map(|(k, v)| {
                let k = k.key.clone();
                let v = v.as_ref().map(|v| v.value.clone());
                (k, v)
            }));
        let post_state =
            stateful_statediff::build_post_state(state_log.iter_ordered_writes().map(|(k, v)| {
                let k = k.key.clone();
                let v = v.as_ref().map(|v| v.value.clone());
                (k, v)
            }));
        let st_statediff = stateful_statediff::compress_state(pre_state, post_state);

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

        let unparsed_len: usize = st_statediff
            .unparsed
            .iter()
            .map(|(_k, v)| if let Some(x) = v { x.len() } else { 0 })
            .sum();
        let ststdiff = borsh::to_vec(&st_statediff).unwrap();
        let prevdiff = borsh::to_vec(&diff).unwrap();

        println!(
            "zk: ststdiff: {} bytes, diff: {} bytes, ststdiff unparsed: {} bytes \n",
            ststdiff.len(),
            prevdiff.len(),
            unparsed_len
        );

        Ok((
            StateRootTransition {
                init_root: prev_state_root,
                final_root: new_root,
            },
            (),
            (diff, st_statediff),
        ))
    }

    fn commit(
        &self,
        _node_batch: &Self::StateUpdate,
        _accessory_writes: &OrderedWrites,
        _offchain_log: &ReadWriteLog,
    ) {
    }

    fn is_empty(&self) -> bool {
        unimplemented!("Needs simplification in JellyfishMerkleTree: https://github.com/Sovereign-Labs/sovereign-sdk/issues/362")
    }

    fn clone_with_version(&self, _version: jmt::Version) -> Self {
        unimplemented!("ZkStorage::clone_with_version should never be called")
    }
}
