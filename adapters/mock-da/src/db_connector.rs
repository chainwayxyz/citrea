use std::collections::HashMap;
use std::env::temp_dir;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use lazy_static::lazy_static;
use rand::Rng;
use rusqlite::{params, Connection, Result};

use crate::{MockBlock, MockBlockHeader, MockHash, MockValidityCond};

lazy_static! {
    static ref used: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());
}

pub(crate) struct DbConnector {
    // thread-safe mysql connection
    conn: Connection,
}

impl DbConnector {
    pub fn new() -> Result<Self> {
        let mut db_name = String::from("shared-mock-da.db");
        let thread = std::thread::current();
        let id = thread.name().unwrap();
        // if cfg!(test) {
        // let random_path: [u8; 8] = rand::thread_rng().gen();

        // // 97..120
        // let random_path: String = random_path.iter().map(|x| (97 + x % 26) as char).collect();

        let dir = temp_dir().join(id.to_owned() + &"shared-mock-da.db".to_string());

        db_name = dir.to_str().unwrap().to_string();
        // }

        tracing::error!("Using test db: {}, id: {}", db_name, id);

        let conn = Connection::open(db_name.clone())?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS blocks (
                    prev_hash BLOB,
                    hash BLOB,
                    height INTEGER unique,
                    time TEXT,
                    is_valid INTEGER,
                    blobs TEXT
                );",
            (),
        )?;

        let mut map = used.lock().unwrap();

        if !map.contains_key(&db_name) {
            tracing::error!("deleting db");
            conn.execute("DELETE FROM blocks", ())?;
            map.insert(db_name, true);
        }

        Ok(Self { conn })
    }

    pub fn push_back(&self, block: MockBlock) -> Result<()> {
        self.conn.execute(
            "INSERT INTO blocks (prev_hash, hash, height, time, is_valid, blobs)
                VALUES (?, ?, ?, ?, ?, ?)",
            (
                &block.header.prev_hash.0,
                &block.header.hash.0,
                &block.header.height,
                &serde_json::to_string(&block.header.time)
                    .expect("DbConnector: Failed to serialize time"),
                &block.validity_cond.is_valid,
                &serde_json::to_string(&block.blobs)
                    .expect("DbConnector: Failed to serialize blobs"),
            ),
        )?;

        Ok(())
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

        match row {
            None => None,
            Some(row) => Some(Self::row_to_block(row)),
        }
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

    pub fn prune_above(&self, height: u64) -> Result<()> {
        self.conn
            .execute("DELETE FROM blocks WHERE height > ?", params![height])?;

        Ok(())
    }

    pub fn last(&self) -> Option<MockBlock> {
        let mut stmt = self
            .conn
            .prepare("SELECT * FROM blocks ORDER BY height DESC LIMIT 1")
            .unwrap();
        let mut rows = stmt.query([]).unwrap();

        let row = rows.next().expect("DbConnector: failed to get last row");

        match row {
            None => None,
            Some(row) => Some(Self::row_to_block(row)),
        }
    }

    #[cfg(test)]
    pub fn delete_all_rows(&self) -> Result<()> {
        self.conn.execute("DELETE FROM blocks", ())?;

        Ok(())
    }

    fn row_to_block(row: &rusqlite::Row) -> MockBlock {
        MockBlock {
            header: MockBlockHeader {
                prev_hash: MockHash(row.get(0).unwrap()),
                hash: MockHash(row.get(1).unwrap()),
                height: row.get(2).unwrap(),
                time: serde_json::from_str(&row.get::<_, String>(3).unwrap().as_str()).unwrap(),
            },
            validity_cond: MockValidityCond {
                is_valid: row.get(4).unwrap(),
            },
            blobs: serde_json::from_str(&row.get::<_, String>(5).unwrap().as_str()).unwrap(),
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
        let db = DbConnector::new().unwrap();

        let block = get_test_block(1);

        db.push_back(block.clone()).unwrap();

        let block_from_db = db.get(0).unwrap();

        println!("{:?}", block);
        println!("{:?}", block_from_db);

        assert_eq!(block, block_from_db);
    }

    #[test]
    fn test_len() {
        let db = DbConnector::new().unwrap();

        let block = get_test_block(1);

        db.push_back(block.clone()).unwrap();

        assert_eq!(db.len(), 1);
    }

    #[test]
    fn test_last() {
        let db = DbConnector::new().unwrap();

        let block = get_test_block(1);

        db.push_back(block.clone()).unwrap();

        let last = db.last().unwrap();
        assert_eq!(last, block);
    }

    #[test]
    fn test_prune_above() {
        let db = DbConnector::new().unwrap();

        let block1 = get_test_block(1);
        let block2 = get_test_block(2);

        db.push_back(block1).unwrap();
        db.push_back(block2).unwrap();

        db.prune_above(2).unwrap();

        assert_eq!(db.len(), 2);

        db.prune_above(1).unwrap();

        assert_eq!(db.len(), 1);
    }

    #[test]
    fn test_same_thread_behaviour() {
        let db = DbConnector::new().unwrap();

        let block = get_test_block(1);

        db.push_back(block.clone()).unwrap();

        let block_from_db = db.get(0).unwrap();

        assert_eq!(block, block_from_db);

        let db2 = DbConnector::new().unwrap();

        // data wasn't wiped
        let block_from_db2 = db2.get(0).unwrap();

        assert_eq!(block, block_from_db2);

        db2.delete_all_rows().unwrap();

        // now it's wiped
        assert_eq!(db2.len(), 0);
    }
}
