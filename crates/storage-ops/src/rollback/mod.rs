pub mod service;

pub struct Rollback {}

impl Rollback {
    /// Rollback the provided number of blocks
    pub fn execute(&self, _num_blocks: u32) -> anyhow::Result<()> {
        // Do something

        Ok(())
    }
}
