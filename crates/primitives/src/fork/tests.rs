use anyhow::anyhow;
use sov_rollup_interface::fork::Fork;
use sov_rollup_interface::spec::SpecId;

use super::ForkManager;
use crate::fork::{fork_from_block_number, ForkMigration};

#[test]
fn test_fork_from_block_number() {
    let forks = vec![
        Fork::new(SpecId::Genesis, 0),
        Fork::new(SpecId::Fork1, 100),
        Fork::new(SpecId::Fork2, 500),
    ];

    assert_eq!(
        fork_from_block_number(forks.clone(), 5).spec_id,
        SpecId::Genesis
    );
    assert_eq!(
        fork_from_block_number(forks.clone(), 105).spec_id,
        SpecId::Fork1
    );
    assert_eq!(
        fork_from_block_number(forks.clone(), 350).spec_id,
        SpecId::Fork1
    );
    assert_eq!(fork_from_block_number(forks, 505).spec_id, SpecId::Fork2);
}

#[test]
fn test_fork_manager() {
    let forks = vec![
        Fork::new(SpecId::Genesis, 0),
        Fork::new(SpecId::Fork1, 100),
        Fork::new(SpecId::Fork2, 500),
    ];
    let mut fork_manager = ForkManager::new(forks, 0);
    fork_manager.register_block(5).unwrap();
    assert_eq!(fork_manager.active_fork().spec_id, SpecId::Genesis);
    fork_manager.register_block(100).unwrap();
    assert_eq!(fork_manager.active_fork().spec_id, SpecId::Fork1);
    fork_manager.register_block(350).unwrap();
    assert_eq!(fork_manager.active_fork().spec_id, SpecId::Fork1);
    fork_manager.register_block(500).unwrap();
    assert_eq!(fork_manager.active_fork().spec_id, SpecId::Fork2);
}

#[test]
fn test_fork_manager_callbacks() {
    let forks = vec![
        Fork::new(SpecId::Genesis, 0),
        Fork::new(SpecId::Fork1, 100),
        Fork::new(SpecId::Fork2, 500),
    ];

    struct Handler {}
    impl ForkMigration for Handler {
        fn fork_activated(&self, fork: &Fork) -> anyhow::Result<()> {
            if fork.spec_id == SpecId::Fork1 {
                return Err(anyhow!("Called"));
            }
            Ok(())
        }
    }
    let handler = Box::new(Handler {});
    let mut fork_manager = ForkManager::new(forks, 0);
    fork_manager.register_handler(handler);
    let result = fork_manager.register_block(100);
    assert!(result.is_err());
    if let Err(msg) = result {
        assert_eq!(msg.to_string(), "Called");
    }
}
