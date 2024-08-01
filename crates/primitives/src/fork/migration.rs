use sov_rollup_interface::spec::SpecId;

/// Defines the interface of a migration
pub trait ForkMigration {
    /// Invoked before a spec is activated.
    fn pre_spec_activation(&self, spec_id: SpecId) -> anyhow::Result<()>;
    /// Invoked after a spec is activated.
    fn post_spec_activation(&self, spec_id: SpecId) -> anyhow::Result<()>;
}

pub struct NoOpMigration {}

impl ForkMigration for NoOpMigration {
    fn pre_spec_activation(&self, _spec_id: SpecId) -> anyhow::Result<()> {
        // Do nothing
        Ok(())
    }

    fn post_spec_activation(&self, _spec_id: SpecId) -> anyhow::Result<()> {
        // Do nothing
        Ok(())
    }
}
