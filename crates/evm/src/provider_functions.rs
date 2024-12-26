use alloy_primitives::Address;
use reth_primitives::{Account, SealedHeader};
use sov_modules_api::{
    AccessoryStateVec, AccessoryWorkingSet, StateMapAccessor, StateVecAccessor, WorkingSet,
};
use sov_state::codec::{BcsCodec, RlpCodec};

use crate::primitive_types::{DoNotUseSealedBlock, SealedBlock};
use crate::Evm;

impl<C: sov_modules_api::Context> Evm<C> {
    /// Returns the account at the given address.
    pub fn basic_account(
        &self,
        address: &Address,
        working_set: &mut WorkingSet<C::Storage>,
    ) -> Option<Account> {
        Some(
            self.accounts
                .get(address, working_set)
                .unwrap_or_default()
                .into(),
        )
    }

    /// Returns the sealed head block.
    pub fn last_sealed_header(&self, working_set: &mut WorkingSet<C::Storage>) -> SealedHeader {
        self.blocks
            .last(&mut working_set.accessory_state())
            .or_else(|| {
                //  upgrading from v0.5.7 to v0.6+ requires a codec change
                // this only applies to the sequencer
                // which will only query the genesis block and the head block
                // right after the upgrade
                let prefix = <AccessoryStateVec<SealedBlock, RlpCodec> as StateVecAccessor<
                    SealedBlock,
                    RlpCodec,
                    AccessoryWorkingSet<C::Storage>,
                >>::prefix(&self.blocks);
                let accessor_with_old_codec =
                    AccessoryStateVec::<DoNotUseSealedBlock, BcsCodec>::with_codec(
                        prefix.clone(),
                        BcsCodec,
                    );

                accessor_with_old_codec
                    .last(&mut working_set.accessory_state())
                    .map(Into::into)
            })
            .unwrap()
            .header
    }
}
