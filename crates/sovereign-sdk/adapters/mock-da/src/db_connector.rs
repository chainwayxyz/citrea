use std::path::Path;

use rusqlite::{params, Connection};
use tracing::debug;

use crate::{MockBlock, MockBlockHeader, MockHash, MockValidityCond};

pub(crate) struct DbConnector {
    // thread-safe sqlite connection
    conn: Connection,
}

impl DbConnector {
    pub fn new(db_path: &Path) -> Self {
        debug!("Using test db: {:?}", db_path);

        let conn =
            Connection::open(db_path.join("mock_da.db")).expect("DbConnector: failed to open db");

        conn.execute(
            "CREATE TABLE IF NOT EXISTS blocks (
                    prev_hash BLOB,
                    hash BLOB,
                    txs_commitment BLOB,
                    height INTEGER unique,
                    time TEXT,
                    is_valid INTEGER,
                    blobs TEXT
                );",
            (),
        )
        .expect("DbConnector: failed to create table");

        Self { conn }
    }

    pub fn push_back(&self, block: MockBlock) {
        self.conn
            .execute(
                "INSERT INTO blocks (prev_hash, hash, txs_commitment, height, time, is_valid, blobs)
                VALUES (?, ?, ?, ?, ?, ?, ?)",
                params![
                    block.header.prev_hash.0,
                    block.header.hash.0,
                    block.header.txs_commitment.0,
                    block.header.height,
                    serde_json::to_string(&block.header.time)
                        .expect("DbConnector: Failed to serialize time"),
                    block.validity_cond.is_valid,
                    serde_json::to_string(&block.blobs)
                        .expect("DbConnector: Failed to serialize blobs"),
                ],
            )
            .expect("DbConnector: failed to execute insert query");
    }

    // service.rs used index so index 0 should get block 1
    pub fn get(&self, index: u64) -> Option<MockBlock> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM blocks WHERE height = ?")
            .unwrap();
        let mut rows = stmt
            .query(params![index + 1])
            .expect("DbConnector: failed to execute query");

        let row = rows.next().expect("DbConnector: failed to get row");

        row.map(|row| Self::row_to_block(row))
    }

    pub fn get_by_hash(&self, hash: [u8; 32]) -> Option<MockBlock> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM blocks WHERE hash = ?")
            .unwrap();
        let mut rows = stmt
            .query(params![hash])
            .expect("DbConnector: failed to execute query");

        let row = rows.next().expect("DbConnector: failed to get row");

        row.map(|row| Self::row_to_block(row))
    }

    pub fn len(&self) -> usize {
        let mut stmt = self
            .conn
            .prepare("SELECT COUNT(*) FROM blocks")
            .expect("DbConnector: failed to execute count row query");
        let count: i64 = stmt
            .query_row([], |row| row.get(0))
            .expect("DbConnector: failed to get count");

        count as usize
    }

    pub fn prune_above(&self, height: u64) {
        self.conn
            .execute("DELETE FROM blocks WHERE height > ?", params![height])
            .expect("DbConnector: failed to prune");
    }

    pub fn last(&self) -> Option<MockBlock> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM blocks ORDER BY height DESC LIMIT 1")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();

        let row = rows.next().expect("DbConnector: failed to get last row");

        row.map(|row| Self::row_to_block(row))
    }

    #[cfg(test)]
    pub fn delete_all_rows(&self) {
        self.conn
            .execute("DELETE FROM blocks", ())
            .expect("DbConnector: failed to delete all rows");
    }

    fn row_to_block(row: &rusqlite::Row) -> MockBlock {
        MockBlock {
            header: MockBlockHeader {
                prev_hash: MockHash(row.get(0).unwrap()),
                hash: MockHash(row.get(1).unwrap()),
                txs_commitment: MockHash(row.get(2).unwrap()),
                height: row.get(3).unwrap(),
                time: serde_json::from_str(row.get::<_, String>(4).unwrap().as_str()).unwrap(),
            },
            validity_cond: MockValidityCond {
                is_valid: row.get(5).unwrap(),
            },
            blobs: serde_json::from_str(row.get::<_, String>(6).unwrap().as_str()).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::db_connector::DbConnector;
    use crate::{MockAddress, MockBlob, MockBlock, MockBlockHeader, MockValidityCond};

    fn get_test_block(at_height: u64) -> MockBlock {
        MockBlock {
            header: MockBlockHeader::from_height(at_height),
            validity_cond: MockValidityCond { is_valid: true },
            blobs: vec![
                MockBlob::new(vec![2; 44], MockAddress::new([1; 32]), [2; 32]),
                MockBlob::new(vec![3; 12], MockAddress::new([2; 32]), [5; 32]),
            ],
        }
    }

    #[test]
    fn test_write_and_read() {
        let db_path = tempfile::tempdir().unwrap();
        let db = DbConnector::new(db_path.path());

        let block = get_test_block(1);

        db.push_back(block.clone());

        let block_from_db = db.get(0).unwrap();

        assert_eq!(block, block_from_db);
    }

    #[test]
    fn test_read_by_hash() {
        let db_path = tempfile::tempdir().unwrap();
        let db = DbConnector::new(db_path.path());

        let block = get_test_block(1);

        db.push_back(block.clone());

        let block_from_db_by_height = db.get(0).unwrap();

        let block_from_db_by_hash = db.get_by_hash(block.header.hash.into()).unwrap();

        assert_eq!(block_from_db_by_height, block_from_db_by_hash);
    }

    #[test]
    fn test_len() {
        let db_path = tempfile::tempdir().unwrap();
        let db = DbConnector::new(db_path.path());

        let block = get_test_block(1);

        db.push_back(block.clone());

        assert_eq!(db.len(), 1);
    }

    #[test]
    fn test_last() {
        let db_path = tempfile::tempdir().unwrap();
        let db = DbConnector::new(db_path.path());

        let block1 = get_test_block(1);
        let block2 = get_test_block(2);

        db.push_back(block1);
        db.push_back(block2.clone());

        let last = db.last().unwrap();
        assert_eq!(last, block2);
    }

    #[test]
    fn test_prune_above() {
        let db_path = tempfile::tempdir().unwrap();
        let db = DbConnector::new(db_path.path());

        let block1 = get_test_block(1);
        let block2 = get_test_block(2);

        db.push_back(block1);
        db.push_back(block2);

        db.prune_above(2);

        assert_eq!(db.len(), 2);

        db.prune_above(1);

        assert_eq!(db.len(), 1);
    }

    #[test]
    fn test_same_thread_behaviour() {
        let db_path = tempfile::tempdir().unwrap();
        let db = DbConnector::new(db_path.path());

        let block = get_test_block(1);

        db.push_back(block.clone());

        let block_from_db = db.get(0).unwrap();

        assert_eq!(block, block_from_db);

        let db2 = DbConnector::new(db_path.path());

        // data wasn't wiped
        let block_from_db2 = db2.get(0).unwrap();

        assert_eq!(block, block_from_db2);

        db2.delete_all_rows();

        // now it's wiped
        assert_eq!(db2.len(), 0);
    }
}
