use anyhow::anyhow;

use super::ForkManager;
use crate::fork::{fork_pos_from_block_number, Fork, ForkMigration};
use crate::spec::SpecId;

#[test]
fn test_fork_pos_from_block_number() {
    static T_FORKS: &[Fork] = &[
        Fork::new(SpecId::Tangerine, 0),
        Fork::new(SpecId::Fork3, 100),
        Fork::new(SpecId::Fork4, 500),
    ];

    assert_eq!(fork_pos_from_block_number(T_FORKS, 5), 0);
    assert_eq!(fork_pos_from_block_number(T_FORKS, 105), 1);
    assert_eq!(fork_pos_from_block_number(T_FORKS, 350), 1);
    assert_eq!(fork_pos_from_block_number(T_FORKS, 505), 2);
}

#[test]
fn test_fork_manager() {
    static T_FORKS: &[Fork] = &[
        Fork::new(SpecId::Tangerine, 0),
        Fork::new(SpecId::Fork3, 100),
        Fork::new(SpecId::Fork4, 500),
    ];
    let mut fork_manager = ForkManager::new(T_FORKS, 0);
    fork_manager.register_block(5).unwrap();
    assert_eq!(fork_manager.active_fork().spec_id, SpecId::Tangerine);
    fork_manager.register_block(100).unwrap();
    assert_eq!(fork_manager.active_fork().spec_id, SpecId::Fork3);
    fork_manager.register_block(350).unwrap();
    assert_eq!(fork_manager.active_fork().spec_id, SpecId::Fork3);
    fork_manager.register_block(500).unwrap();
    assert_eq!(fork_manager.active_fork().spec_id, SpecId::Fork4);
}

#[test]
fn test_fork_manager_callbacks() {
    static T_FORKS: &[Fork] = &[
        Fork::new(SpecId::Tangerine, 0),
        Fork::new(SpecId::Fork3, 100),
        Fork::new(SpecId::Fork4, 500),
    ];

    struct Handler {}
    impl ForkMigration for Handler {
        fn fork_activated(&self, fork: &Fork) -> anyhow::Result<()> {
            if fork.spec_id == SpecId::Fork3 {
                return Err(anyhow!("Called"));
            }
            Ok(())
        }
    }
    let handler = Box::new(Handler {});
    let mut fork_manager = ForkManager::new(T_FORKS, 0);
    fork_manager.register_handler(handler);
    let result = fork_manager.register_block(100);
    assert!(result.is_err());
    if let Err(msg) = result {
        assert_eq!(msg.to_string(), "Called");
    }
}
