use jsonrpsee::tracing::warn;
use sov_modules_api::hooks::ApplySoftConfirmationHooks;
use sov_modules_api::{BlobReaderTrait, Context, SignedSoftConfirmationBatch, WorkingSet};
#[cfg(all(target_os = "zkvm", feature = "bench"))]
use sov_zk_cycle_macros::cycle_tracker;
#[cfg(all(target_os = "zkvm", feature = "bench"))]
use sov_zk_cycle_utils::print_cycle_count;

use crate::{SequencerOutcome, SequencerRegistry};

impl<C: Context, Da: sov_modules_api::DaSpec> ApplySoftConfirmationHooks<Da>
    for SequencerRegistry<C, Da>
{
    type Context = C;
    type SoftConfirmationResult = SequencerOutcome<Da>;

    #[cfg_attr(all(target_os = "zkvm", feature = "bench"), cycle_tracker)]
    fn begin_soft_confirmation_hook(
        &self,
        soft_batch: &mut SignedSoftConfirmationBatch,
        working_set: &mut WorkingSet<Self::Context>,
    ) -> anyhow::Result<()> {
        #[cfg(all(target_os = "zkvm", feature = "bench"))]
        print_cycle_count();
        // TODO
        // if !self.is_sender_allowed(&soft_batch.sequencer_pub_key(), working_set) {
        //     anyhow::bail!(
        //         "sender {:?} is not allowed to submit blobs",
        //         soft_batch.sequencer_pub_key()
        //     );
        // }
        #[cfg(all(target_os = "zkvm", feature = "bench"))]
        print_cycle_count();
        Ok(())
    }

    fn end_soft_confirmation_hook(
        &self,
        result: Self::SoftConfirmationResult,
        working_set: &mut WorkingSet<Self::Context>,
    ) -> anyhow::Result<()> {
        match result {
            SequencerOutcome::Completed => (),
            SequencerOutcome::Slashed { sequencer } => {
                self.delete(&sequencer, working_set);
            }
        }
        Ok(())
    }
}
