use borsh::{BorshDeserialize, BorshSerialize};
use sov_modules_api::{CallResponse, Context, DaSpec, StateValueAccessor, WorkingSet};

use crate::SoftConfirmationRuleEnforcer;

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize),
    derive(serde::Deserialize)
)]
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, Eq, PartialEq)]
pub enum CallMessage<C: Context> {
    /// Change the authority of soft confirmation rule enforcing.
    ChangeAuthority {
        /// The sov address of the new authority.
        new_authority: C::Address,
    },
    /// Remove a sequencer from the sequencer registry.
    ModifyLimitingNumber {
        /// The new limiting number representing max number of L2 blocks published per L1 block.
        limiting_number: u64,
    },
}

impl<C: Context, Da: DaSpec> SoftConfirmationRuleEnforcer<C, Da> {
    pub(crate) fn change_authority(
        &self,
        address: C::Address,
        context: &C,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<CallResponse> {
        let sender = context.sender();
        if *sender
            != self
                .authority
                .get(working_set)
                .expect("Authority must be set")
        {
            return Err(anyhow::anyhow!("Only authority can change the authority"));
        }
        self.authority.set(&address, working_set);
        Ok(CallResponse::default())
    }

    pub(crate) fn modify_limiting_number(
        &self,
        limiting_number: u64,
        context: &C,
        working_set: &mut WorkingSet<C>,
    ) -> anyhow::Result<CallResponse> {
        let sender = context.sender();
        if *sender
            != self
                .authority
                .get(working_set)
                .expect("Authority must be set")
        {
            return Err(anyhow::anyhow!(
                "Only authority can change the limiting number"
            ));
        }
        self.limiting_number.set(&limiting_number, working_set);
        Ok(CallResponse::default())
    }
}
