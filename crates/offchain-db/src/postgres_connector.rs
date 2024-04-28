use postgres::Error;
use postgres::{Client, NoTls, Row};

use crate::config::OffchainDbConfig;
use crate::tables::{DbSequencerCommitment, Tables, SEQUENCER_COMMITMENT_TABLE};

pub struct PostgresConnector {
    client: Client,
}

impl PostgresConnector {
    pub fn new(pg_config: OffchainDbConfig) -> Result<Self, Error> {
        let mut client = Client::connect(pg_config.parse_to_connection_string().as_str(), NoTls)?;
        // create tables
        client.batch_execute(SEQUENCER_COMMITMENT_TABLE)?;
        Ok(Self { client })
    }

    pub fn insert_sequencer_commitment(
        &mut self,
        l1_tx_id: String,
        l1_start_height: u32,
        l1_end_height: u32,
        l1_start_hash: Vec<u8>,
        l1_end_hash: Vec<u8>,
        l2_start_height: u32,
        l2_end_height: u32,
        merkle_root: Vec<u8>,
        status: String,
    ) -> Result<u64, Error> {
        Ok(self.client
            .execute(
                "INSERT INTO sequencer_commitment (l1_tx_id, l1_start_height, l1_end_height l1_start_hash, l1_end_hash, l2_start_height, l2_end_height, merkle_root, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                &[
                    &l1_tx_id,
                    &l1_start_height,
                    &l1_end_height,
                    &hex::encode(l1_start_hash),
                    &hex::encode(l1_end_hash),
                    &l2_start_height,
                    &l2_end_height,
                    &hex::encode(merkle_root),
                    &status,
                ],
            )?)
    }

    pub fn get_all_commitments(&mut self) -> Result<Vec<DbSequencerCommitment>, Error> {
        Ok(self
            .client
            .query("SELECT * FROM sequencer_commitment", &[])?
            .iter()
            .map(|row| PostgresConnector::row_to_sequencer_commitment(row))
            .collect())
    }

    pub fn get_last_commitment(&mut self) -> Result<Option<DbSequencerCommitment>, Error> {
        let rows = self.client.query(
            "SELECT * FROM sequencer_commitment ORDER BY id DESC LIMIT 1",
            &[],
        )?;
        if rows.is_empty() {
            return Ok(None);
        }
        Ok(Some(PostgresConnector::row_to_sequencer_commitment(
            &rows[0],
        )))
    }

    pub fn get_all_from(&mut self, table: Tables) -> Vec<Row> {
        self.client
            .query(format!("SELECT * FROM {}", table.to_string()).as_str(), &[])
            .unwrap_or(vec![])
    }

    pub fn drop_table(&mut self, table: Tables) {
        self.client
            .execute(format!("DROP TABLE {};", table.to_string()).as_str(), &[])
            .unwrap();
    }

    // Helper function to convert a Row to DbSequencerCommitment
    fn row_to_sequencer_commitment(row: &Row) -> DbSequencerCommitment {
        DbSequencerCommitment {
            l1_tx_id: row.get("l1_tx_id"),
            l1_start_heiht: row.get("l1_start_height"),
            l1_end_height: row.get("l1_end_height"),
            l1_start_hash: row.get("l1_start_hash"),
            l1_end_hash: row.get("l1_end_hash"),
            // postgres does not support u64
            l2_start_height: row.get::<&str, u32>("l2_start_height") as u64,
            l2_end_height: row.get::<&str, u32>("l2_end_height") as u64,
            merkle_root: row.get("merkle_root"),
            status: row.get("status"),
        }
    }
}

// #[cfg(feature = "offchain_db")]
// mod tests {
//     use super::*;

//     fn drop_table() {
//         let cfg = OffchainDbConfig::new(
//             "localhost".to_string(),
//             5432,
//             "postgres".to_string(),
//             "postgres".to_string(),
//             "postgres".to_string(),
//         );
//         let mut connector = PostgresConnector::new(cfg).unwrap();
//         connector.drop_table(Tables::SequencerCommitment);
//     }

//     #[test]
//     fn test_insert_sequencer_commitment() {
//         drop_table();
//         let cfg = OffchainDbConfig::new(
//             "localhost".to_string(),
//             5432,
//             "postgres".to_string(),
//             "postgres".to_string(),
//             "postgres".to_string(),
//         );
//         let mut connector = PostgresConnector::new(cfg).unwrap();

//         let inserted = connector
//             .insert_sequencer_commitment(
//                 "0xaabab".to_string(),
//                 vec![255; 32],
//                 vec![0; 32],
//                 10,
//                 11,
//                 vec![1; 32],
//                 "Trusted".to_string(),
//             )
//             .unwrap();

//         assert_eq!(inserted, 1);

//         let rows = connector.get_all_commitments().unwrap();
//         assert_eq!(rows.len(), 1);
//         assert_eq!(rows[0].l1_tx_id, "0xaabab");
//         assert_eq!(rows[0].l1_start_hash, hex::encode(vec![255; 32]));
//         assert_eq!(rows[0].l1_start_hash, "ff".repeat(32));
//         assert_eq!(rows[0].l1_end_hash, hex::encode(vec![0; 32]));
//         assert_eq!(rows[0].l2_start_height, 10);
//         assert_eq!(rows[0].l2_end_height, 11);
//         for row in rows {
//             println!("{:?}", row);
//             println!("{:?}", hex::decode(row.l1_end_hash));
//         }
//     }
// }
