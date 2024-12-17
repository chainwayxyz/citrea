use anyhow::anyhow;

use super::{ForkManager, Forks};
use crate::fork::{fork_from_block_number, Fork, ForkMigration};
use crate::spec::SpecId;

#[test]
fn test_fork_from_block_number() {
    static T_FORKS: &[Fork] = &[
        Fork::new(SpecId::Genesis, 0),
        Fork::new(SpecId::Fork1, 100),
        Fork::new(SpecId::Fork2, 500),
    ];

    assert_eq!(fork_from_block_number(T_FORKS, 5).spec_id, SpecId::Genesis);
    assert_eq!(fork_from_block_number(T_FORKS, 105).spec_id, SpecId::Fork1);
    assert_eq!(fork_from_block_number(T_FORKS, 350).spec_id, SpecId::Fork1);
    assert_eq!(fork_from_block_number(T_FORKS, 505).spec_id, SpecId::Fork2);
}

#[test]
fn test_fork_manager() {
    static T_FORKS: &[Fork] = &[
        Fork::new(SpecId::Genesis, 0),
        Fork::new(SpecId::Fork1, 100),
        Fork::new(SpecId::Fork2, 500),
    ];
    let mut fork_manager = ForkManager::new(T_FORKS, 0);
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
    static T_FORKS: &[Fork] = &[
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
    let mut fork_manager = ForkManager::new(T_FORKS, 0);
    fork_manager.register_handler(handler);
    let result = fork_manager.register_block(100);
    assert!(result.is_err());
    if let Err(msg) = result {
        assert_eq!(msg.to_string(), "Called");
    }
}

#[test]
fn test_fork_parse_utf8() {
    let max64 = u64::MAX.to_string();
    let max64plusone = ((u64::MAX as u128) + 1).to_string();

    assert_fork_parse_utf8(b"0:0", 0, 0);
    assert_fork_parse_utf8(b"1:1000", 1, 1000);
    assert_fork_parse_utf8(b"1:1", 1, 1);
    assert_fork_parse_utf8(b"2:1234567890", 2, 1234567890);
    assert_fork_parse_utf8(b"0:110", 0, 110);
    assert_fork_parse_utf8(format!("1:{}", max64).as_bytes(), 1, u64::MAX);

    assert!(Fork::from_colon_separated_utf8(b"").is_none());
    assert!(Fork::from_colon_separated_utf8(b":").is_none());
    assert!(Fork::from_colon_separated_utf8(b":123").is_none());
    assert!(Fork::from_colon_separated_utf8(b"1:").is_none());
    assert!(Fork::from_colon_separated_utf8(b"01:123").is_none());
    assert!(Fork::from_colon_separated_utf8(b"1:01234").is_none());
    assert!(Fork::from_colon_separated_utf8(b"256:123").is_none());
    assert!(Fork::from_colon_separated_utf8(b"5:123").is_none());
    assert!(Fork::from_colon_separated_utf8(b"ab:cd").is_none());
    assert!(Fork::from_colon_separated_utf8(b"1:123a").is_none());
    assert!(Fork::from_colon_separated_utf8(b"12345").is_none());
    assert!(Fork::from_colon_separated_utf8(format!("1:{}", max64plusone).as_bytes()).is_none());
}

fn assert_fork_parse_utf8(bytes: &[u8], exp_spec: u8, exp_height: u64) {
    let fork = Fork::from_colon_separated_utf8(bytes).unwrap();
    assert_eq!(fork.spec_id, SpecId::from_u8(exp_spec).unwrap());
    assert_eq!(fork.activation_height, exp_height);
}

#[test]
fn test_fork_parse_list() {
    assert_fork_parse_list("0:0", &[(0, 0)]);
    assert_fork_parse_list("0:0,1:456", &[(0, 0), (1, 456)]);
    assert_fork_parse_list("0:0,1:1,2:2", &[(0, 0), (1, 1), (2, 2)]);
    assert_fork_parse_list("1:0,2:123", &[(1, 0), (2, 123)]);

    assert!(Forks::from_utf8("").is_none());
    assert!(Forks::from_utf8("0123").is_none());
    assert!(Forks::from_utf8("01:123").is_none());
    assert!(Forks::from_utf8("0:123,1:456").is_none());
    assert!(Forks::from_utf8("0:0 1:456").is_none());
    assert!(Forks::from_utf8("0:0,1:456,").is_none());
    assert!(Forks::from_utf8("0:0,2:456,1:789").is_none());
    assert!(Forks::from_utf8("0:0,1:456,2:123").is_none());
}

fn assert_fork_parse_list(s: &str, exp_list: &[(u8, u64)]) {
    let forks = Forks::from_utf8(s).unwrap();
    let forks = forks.inner();
    assert_eq!(forks.len(), exp_list.len());

    for (fork, exp_fork) in forks.iter().zip(exp_list) {
        assert_eq!(fork.spec_id as u8, exp_fork.0);
        assert_eq!(fork.activation_height, exp_fork.1);
    }
}
