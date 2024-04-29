use postgres::Error;
use tokio_postgres::{Client, NoTls, Row};

use crate::config::OffchainDbConfig;
use crate::tables::{DbSequencerCommitment, Tables, SEQUENCER_COMMITMENT_TABLE_CREATE_QUERY};
use crate::utils::get_db_extension;

pub struct PostgresConnector {
    client: Client,
}

impl PostgresConnector {
    pub async fn new(pg_config: OffchainDbConfig) -> Result<Self, Error> {
        let (client, connection) =
            tokio_postgres::connect(pg_config.parse_to_connection_string().as_str(), NoTls).await?;

        // The connection object performs the actual communication with the database,
        // so spawn it off to run on its own.
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });
        // create new db
        let db_name = format!("citrea{}", get_db_extension());
        let _ = client
            .batch_execute(&format!("CREATE DATABASE {};", db_name.clone()))
            .await;
        drop(client);
        //connect to new db
        let (client, connection) = tokio_postgres::connect(
            pg_config
                .parse_to_connection_string_with_db(db_name)
                .as_str(),
            NoTls,
        )
        .await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });

        // create tables
        client
            .batch_execute(SEQUENCER_COMMITMENT_TABLE_CREATE_QUERY)
            .await?;
        Ok(Self { client })
    }

    pub async fn new_test_client() -> Result<Self, Error> {
        let pg_config = OffchainDbConfig::default();

        let (client, connection) =
            tokio_postgres::connect(pg_config.parse_to_connection_string().as_str(), NoTls).await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });

        // create new db
        let db_name = format!("citrea{}", get_db_extension());
        let _ = client
            .batch_execute(&format!("DROP DATABASE {};", db_name.clone()))
            .await;

        let _ = client
            .batch_execute(&format!("CREATE DATABASE {};", db_name.clone()))
            .await;
        drop(client);
        //connect to new db
        let (test_client, connection) = tokio_postgres::connect(
            pg_config
                .parse_to_connection_string_with_db(db_name)
                .as_str(),
            NoTls,
        )
        .await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });
        Ok(Self {
            client: test_client,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_sequencer_commitment(
        &self,
        l1_start_height: u32,
        l1_end_height: u32,
        l1_tx_id: String,
        l1_start_hash: Vec<u8>,
        l1_end_hash: Vec<u8>,
        l2_start_height: u32,
        l2_end_height: u32,
        merkle_root: Vec<u8>,
        status: String,
    ) -> Result<u64, Error> {
        self.client
            .execute(
                "INSERT INTO sequencer_commitment (l1_start_height, l1_end_height, l1_tx_id, l1_start_hash, l1_end_hash, l2_start_height, l2_end_height, merkle_root, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)", 
                &[
                    &l1_start_height,
                    &l1_end_height,
                    &l1_tx_id,
                    &hex::encode(l1_start_hash),
                    &hex::encode(l1_end_hash),
                    &l2_start_height,
                    &l2_end_height,
                    &hex::encode(merkle_root),
                    &status,
                ],
            ).await
    }

    pub async fn get_all_commitments(&self) -> Result<Vec<DbSequencerCommitment>, Error> {
        Ok(self
            .client
            .query("SELECT * FROM sequencer_commitment", &[])
            .await?
            .iter()
            .map(PostgresConnector::row_to_sequencer_commitment)
            .collect())
    }

    pub async fn get_last_commitment(&self) -> Result<Option<DbSequencerCommitment>, Error> {
        let rows = self
            .client
            .query(
                "SELECT * FROM sequencer_commitment ORDER BY id DESC LIMIT 1",
                &[],
            )
            .await?;
        if rows.is_empty() {
            return Ok(None);
        }
        Ok(Some(PostgresConnector::row_to_sequencer_commitment(
            &rows[0],
        )))
    }

    pub async fn drop_table(&self, table: Tables) -> Result<u64, Error> {
        self.client
            .execute(format!("DROP TABLE {};", table).as_str(), &[])
            .await
    }

    #[cfg(test)]
    pub async fn create_sequencer_commitments_table(&self) {
        self.client
            .execute(SEQUENCER_COMMITMENT_TABLE_CREATE_QUERY, &[])
            .await
            .unwrap();
    }

    // Helper function to convert a Row to DbSequencerCommitment
    fn row_to_sequencer_commitment(row: &Row) -> DbSequencerCommitment {
        DbSequencerCommitment {
            l1_tx_id: row.get("l1_tx_id"),
            l1_start_height: row.get("l1_start_height"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::Tables;

    #[tokio::test]
    async fn test_insert_sequencer_commitment() {
        let client = PostgresConnector::new_test_client().await.unwrap();

        let _ = client.drop_table(Tables::SequencerCommitment).await;
        client.create_sequencer_commitments_table().await;

        let inserted = client
            .insert_sequencer_commitment(
                3,
                4,
                "0xaabab".to_string(),
                vec![255; 32],
                vec![0; 32],
                10,
                11,
                vec![1; 32],
                "Trusted".to_string(),
            )
            .await
            .unwrap();

        assert_eq!(inserted, 1);

        let rows = client.get_all_commitments().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].l1_tx_id, "0xaabab");
        assert_eq!(rows[0].l1_start_hash, hex::encode(vec![255; 32]));
        assert_eq!(rows[0].l1_start_hash, "ff".repeat(32));
        assert_eq!(rows[0].l1_end_hash, hex::encode(vec![0; 32]));
        assert_eq!(rows[0].l2_start_height, 10);
        assert_eq!(rows[0].l2_end_height, 11);

        let _ = client.drop_table(Tables::SequencerCommitment).await;
    }
}
