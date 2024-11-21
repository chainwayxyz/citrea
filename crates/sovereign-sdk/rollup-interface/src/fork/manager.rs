use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use super::{Fork, ForkMigration};

pub struct ForkManager {
    forks: &'static [Fork],
    active_fork_idx: usize,
    migration_handlers: Vec<Box<dyn ForkMigration + Sync + Send>>,
}

impl ForkManager {
    pub fn new(forks: &'static [Fork], current_l2_height: u64) -> Self {
        // FORKS from citrea-primitives are checked at compile time to be sorted.

        let pos = forks.binary_search_by(|fork| fork.activation_height.cmp(&current_l2_height));
        let active_fork_idx = match pos {
            Ok(idx) => idx,
            Err(idx) => idx.saturating_sub(1),
        };

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

/// Simple search for the fork to which a specific block number blongs.
/// This assumes that the list of forks is sorted by block number in ascending fashion.
pub fn fork_from_block_number(forks: &'static [Fork], block_number: u64) -> Fork {
    ForkManager::new(forks, block_number).active_fork()
}
