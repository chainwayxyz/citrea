use sov_rollup_interface::fork::Fork;

use super::ForkMigration;

pub struct ForkManager {
    forks: Vec<Fork>,
    active_fork_idx: usize,
    migration_handlers: Vec<Box<dyn ForkMigration + Sync + Send>>,
}

impl ForkManager {
    pub fn new(mut forks: Vec<Fork>, current_l2_height: u64) -> Self {
        // Make sure the list of specs is sorted by the block number at which they activate.
        forks.sort_by_key(|fork| fork.activation_height);

        let mut active_fork_idx = 0;
        for (idx, fork) in forks.iter().enumerate() {
            if current_l2_height >= fork.activation_height {
                active_fork_idx = idx;
            } else {
                break;
            }
        }

        Self {
            forks,
            active_fork_idx,
            migration_handlers: vec![],
        }
    }

    pub fn register_handler(&mut self, handler: Box<dyn ForkMigration + Sync + Send>) {
        self.migration_handlers.push(handler);
    }

    pub fn active_fork(&self) -> &Fork {
        &self.forks[self.active_fork_idx]
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

        for handler in self.migration_handlers.iter() {
            handler.fork_activated(next_fork)?;
        }

        self.active_fork_idx = next_fork_idx;

        Ok(())
    }
}

/// Simple search for the fork to which a specific block number blongs.
/// This assumes that the list of forks is sorted by block number in ascending fashion.
pub fn fork_from_block_number(forks: Vec<Fork>, block_number: u64) -> Fork {
    ForkManager::new(forks, block_number).active_fork().clone()
}
