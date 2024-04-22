use sov_modules_api::hooks::{ApplySoftConfirmationError, HookSoftConfirmationInfo};
use sov_modules_api::{Context, DaSpec, StateMapAccessor, StateValueAccessor, WorkingSet};
use sov_state::Storage;

use crate::SoftConfirmationRuleEnforcer;

impl<C: Context, Da: DaSpec> SoftConfirmationRuleEnforcer<C, Da>
where
    <C::Storage as Storage>::Root: Into<[u8; 32]>,
{
    struct SoftConfirmationHookArgs<'a> {
        soft_batch: &'a mut HookSoftConfirmationInfo,
        working_set: &'a mut WorkingSet<C>,
    }

    /// Logic executed at the beginning of the soft confirmation.
    /// Checks three rules: block count rule, fee rate rule, and DA height and hash rule.
    pub fn begin_soft_confirmation_hook(
        &self,
        args: &mut SoftConfirmationHookArgs,
    ) -> Result<(), ApplySoftConfirmationError> {
        self.apply_block_count_rule(args.soft_batch, args.working_set)?;
        self.apply_fee_rate_rule(args.soft_batch, args.working_set)?;
        self.apply_da_height_and_hash_rule(args.soft_batch, args.working_set)?;
        self.apply_timestamp_rule(args.soft_batch, args.working_set)?;

        Ok(())
    }

    // Other methods remain the same
}

// Usage of the begin_soft_confirmation_hook method
fn main() {
    // Create necessary objects and variables
    let mut soft_batch_info = HookSoftConfirmationInfo::new();
    let mut working_set = WorkingSet::new();

    // Create SoftConfirmationHookArgs struct with the required references
    let mut hook_args = SoftConfirmationRuleEnforcer::SoftConfirmationHookArgs {
        soft_batch: &mut soft_batch_info,
        working_set: &mut working_set,
    };

    // Call the begin_soft_confirmation_hook method with the SoftConfirmationHookArgs
    let enforcer = SoftConfirmationRuleEnforcer::new();
    let result = enforcer.begin_soft_confirmation_hook(&mut hook_args);

    // Handle the result accordingly
    match result {
        Ok(()) => {
            // Soft confirmation logic executed successfully
        }
        Err(error) => {
            // Handle the ApplySoftConfirmationError
            println!("Error: {:?}", error);
        }
    }
}
