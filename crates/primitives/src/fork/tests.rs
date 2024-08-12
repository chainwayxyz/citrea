use anyhow::anyhow;
use sov_rollup_interface::spec::SpecId;

use super::{Fork, ForkManager};
use crate::fork::{fork_from_block_number, ForkMigration};

#[test]
fn test_fork_from_block_number() {
    let forks = vec![
        (SpecId::Genesis, 0),
        (SpecId::Fork1, 100),
        (SpecId::Fork2, 500),
    ];

    assert_eq!(fork_from_block_number(&forks, 5), SpecId::Genesis);
    assert_eq!(fork_from_block_number(&forks, 105), SpecId::Fork1);
    assert_eq!(fork_from_block_number(&forks, 350), SpecId::Fork1);
    assert_eq!(fork_from_block_number(&forks, 505), SpecId::Fork2);
}

#[test]
fn test_fork_manager() {
    let forks = vec![
        (SpecId::Genesis, 0),
        (SpecId::Fork1, 100),
        (SpecId::Fork2, 500),
    ];
    let mut fork_manager = ForkManager::new(0, SpecId::Genesis, forks);
    fork_manager.register_block(5).unwrap();
    assert_eq!(fork_manager.active_fork(), SpecId::Genesis);
    fork_manager.register_block(100).unwrap();
    assert_eq!(fork_manager.active_fork(), SpecId::Fork1);
    fork_manager.register_block(350).unwrap();
    assert_eq!(fork_manager.active_fork(), SpecId::Fork1);
    fork_manager.register_block(500).unwrap();
    assert_eq!(fork_manager.active_fork(), SpecId::Fork2);
}

#[test]
fn test_fork_manager_callbacks() {
    let forks = vec![
        (SpecId::Genesis, 0),
        (SpecId::Fork1, 100),
        (SpecId::Fork2, 500),
    ];

    struct Handler {}
    impl ForkMigration for Handler {
        fn spec_activated(&self, spec_id: SpecId) -> anyhow::Result<()> {
            if spec_id == SpecId::Fork1 {
                return Err(anyhow!("Called"));
            }
            Ok(())
        }
    }
    let handler = Box::new(Handler {});
    let mut fork_manager = ForkManager::new(0, SpecId::Genesis, forks);
    fork_manager.register_handler(handler);
    let result = fork_manager.register_block(100);
    assert!(result.is_err());
    if let Err(msg) = result {
        assert_eq!(msg.to_string(), "Called");
    }
}
