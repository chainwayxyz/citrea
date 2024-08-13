use sov_rollup_interface::spec::SpecId;

/// Defines the interface of a migration
pub trait ForkMigration {
    /// Invoked when a spec is activated.
    fn spec_activated(&self, spec_id: SpecId) -> anyhow::Result<()>;
}

pub struct NoOpMigration {}

impl ForkMigration for NoOpMigration {
    fn spec_activated(&self, _spec_id: SpecId) -> anyhow::Result<()> {
        // Do nothing
        Ok(())
    }
}
