use anyhow::anyhow;
use sov_modules_api::{Spec, StateMapAccessor, WorkingSet};
use sov_state::Storage;

use crate::SoftConfirmationRuleEnforcer;

impl<C: sov_modules_api::Context> SoftConfirmationRuleEnforcer<C>
where
    <C::Storage as Storage>::Root: Into<[u8; 32]>,
{
    /// Logic executed at the beginning of the slot.
    /// Here we check if the number of L2 blocks published for the
    /// L1 block with given DA root hash is less than the limiting number.
    pub fn begin_slot_hook(
        &self,
        da_root_hash: [u8; 32],
        _pre_state_root: &<<C as Spec>::Storage as Storage>::Root,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<()> {
        let l2_block_count = self
            .get_block_count_by_da_root_hash(da_root_hash.clone(), working_set)
            .expect("Block count must be set by da root hash must be set");
        let limiting_number = self
            .get_limiting_number(working_set)
            .expect("Limiting number must be set");

        // Adding one more l2 block will exceed the limiting number
        if l2_block_count + 1 > limiting_number {
            // block count per l1 block should not be more than limiting number
            return Err(anyhow!(
                "Block count per l1 block {} should not be more than limiting number {}",
                l2_block_count,
                limiting_number
            ));
        }
        // increment the block count
        self.da_root_hash_to_number
            .set(&da_root_hash, &(l2_block_count + 1), working_set);
        Ok(())
    }
}
