use std::thread::sleep;
use std::time::Duration;

use sov_db::ledger_db::LedgerDB;
use sov_db::rocks_db_config::RocksdbConfig;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::criteria::{Criteria, DistanceCriteria};
use crate::{Pruner, PruningConfig};

#[tokio::test(flavor = "multi_thread")]
async fn test_pruner_simple_run() {
    let tmpdir = tempfile::tempdir().unwrap();
    let (sender, receiver) = broadcast::channel(1);
    let cancellation_token = CancellationToken::new();

    let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(tmpdir.path(), None, None)).unwrap();
    let pruner = Pruner::new(PruningConfig { distance: 5 }, 0, receiver, ledger_db);

    tokio::spawn(pruner.run(cancellation_token.clone()));

    sleep(Duration::from_secs(1));

    for i in 1..=10 {
        let _ = sender.send(i);
    }

    sleep(Duration::from_secs(1));

    cancellation_token.cancel();
}

#[test]
pub fn test_should_prune() {
    let criteria = DistanceCriteria { distance: 1000 };
    assert_eq!(criteria.should_prune(0, 1000), None);
    assert_eq!(criteria.should_prune(0, 2000), None);
    assert_eq!(criteria.should_prune(0, 2001), Some(1000));

    assert_eq!(criteria.should_prune(1000, 2000), None);
    assert_eq!(criteria.should_prune(1000, 3000), None);
    assert_eq!(criteria.should_prune(1000, 3001), Some(2000));
}
