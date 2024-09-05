use super::Fork;

/// Defines the interface of a migration
pub trait ForkMigration {
    /// Invoked when a fork is activated.
    fn fork_activated(&self, fork: &Fork) -> anyhow::Result<()>;
}

pub struct NoOpMigration {}

impl ForkMigration for NoOpMigration {
    fn fork_activated(&self, _fork: &Fork) -> anyhow::Result<()> {
        // Do nothing
        Ok(())
    }
}
