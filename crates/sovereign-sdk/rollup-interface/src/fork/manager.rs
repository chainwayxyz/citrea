use super::{fork_pos_from_block_number, verify_forks, Fork, ForkMigration};

pub struct ForkManager<'a> {
    forks: &'a [Fork],
    active_fork_idx: usize,
    migration_handlers: Vec<Box<dyn ForkMigration + Sync + Send>>,
}

impl<'a> ForkManager<'a> {
    /// Creates new `ForkManager`. Forks are expected to be in ascending order, if not, panics in debug mode.
    pub fn new(forks: &'a [Fork], current_l2_height: u64) -> Self {
        debug_assert!(verify_forks(forks), "Forks must be ordered correctly");

        let active_fork_idx = fork_pos_from_block_number(forks, current_l2_height);

        Self {
            forks,
            active_fork_idx,
            migration_handlers: vec![],
        }
    }

    pub fn register_handler(&mut self, handler: Box<dyn ForkMigration + Sync + Send>) {
        self.migration_handlers.push(handler);
    }

    pub fn active_fork(&self) -> Fork {
        self.forks[self.active_fork_idx]
    }

    pub fn next_fork(&self) -> Option<&Fork> {
        self.forks.get(self.active_fork_idx + 1)
    }

    pub fn register_block(&mut self, height: u64) -> anyhow::Result<()> {
        // Skip if we are already at the last fork
        if self.active_fork_idx == self.forks.len() - 1 {
            return Ok(());
        }

        let next_fork_idx = self.active_fork_idx + 1;
        let next_fork = &self.forks[next_fork_idx];
        if height < next_fork.activation_height {
            return Ok(());
        }

        #[cfg(feature = "native")]
        tracing::info!(
            "Activating fork {:?} at height: {}",
            next_fork.spec_id,
            height
        );

        for handler in self.migration_handlers.iter() {
            handler.fork_activated(next_fork)?;
        }

        self.active_fork_idx = next_fork_idx;

        Ok(())
    }
}
