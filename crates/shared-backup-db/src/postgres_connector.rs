use std::str::FromStr;

use postgres::Error;
use tokio_postgres::{Client, NoTls, Row};

use crate::config::SharedBackupDbConfig;
use crate::tables::{
    CommitmentStatus, DbSequencerCommitment, Tables, INDEX_L1_END_HASH, INDEX_L1_END_HEIGHT,
    INDEX_L2_END_HEIGHT, MEMPOOL_TXS_TABLE_CREATE_QUERY, SEQUENCER_COMMITMENT_TABLE_CREATE_QUERY,
};
use crate::utils::get_db_extension;

pub struct PostgresConnector {
    client: Client,
}

impl PostgresConnector {
    pub async fn new(pg_config: SharedBackupDbConfig) -> Result<Self, Error> {
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
        client.batch_execute(MEMPOOL_TXS_TABLE_CREATE_QUERY).await?;
        let db_client = Self { client };

        let _ = db_client.create_indexes().await;

        Ok(db_client)
    }

    pub async fn create_indexes(&self) -> Result<(), Error> {
        self.client.batch_execute(INDEX_L1_END_HEIGHT).await?;
        self.client.batch_execute(INDEX_L1_END_HASH).await?;
        self.client.batch_execute(INDEX_L2_END_HEIGHT).await?;
        Ok(())
    }

    #[cfg(feature = "test-utils")]
    pub async fn new_test_client() -> Result<Self, Error> {
        let pg_config = SharedBackupDbConfig::default();

        let (client, connection) =
            tokio_postgres::connect(pg_config.parse_to_connection_string().as_str(), NoTls).await?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("connection error: {}", e);
            }
        });

        // create new db
        let db_name = format!("citrea{}", get_db_extension());
        client
            .batch_execute(&format!("DROP DATABASE IF EXISTS {};", db_name.clone()))
            .await
            .unwrap();

        client
            .batch_execute(&format!("CREATE DATABASE {};", db_name.clone()))
            .await
            .unwrap();

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
        test_client
            .batch_execute(SEQUENCER_COMMITMENT_TABLE_CREATE_QUERY)
            .await
            .unwrap();
        test_client
            .batch_execute(MEMPOOL_TXS_TABLE_CREATE_QUERY)
            .await
            .unwrap();
        let test_client = Self {
            client: test_client,
        };

        test_client.create_indexes().await.unwrap();
        Ok(test_client)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_sequencer_commitment(
        &self,
        l1_start_height: u32,
        l1_end_height: u32,
        l1_tx_id: Vec<u8>,
        l1_start_hash: Vec<u8>,
        l1_end_hash: Vec<u8>,
        l2_start_height: u32,
        l2_end_height: u32,
        merkle_root: Vec<u8>,
        status: CommitmentStatus,
    ) -> Result<u64, Error> {
        self.client
            .execute(
                "INSERT INTO sequencer_commitments (l1_start_height, l1_end_height, l1_tx_id, l1_start_hash, l1_end_hash, l2_start_height, l2_end_height, merkle_root, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)", 
                &[
                    &l1_start_height,
                    &l1_end_height,
                    &l1_tx_id,
                    &l1_start_hash,
                    &l1_end_hash,
                    &l2_start_height,
                    &l2_end_height,
                    &merkle_root,
                    &status.to_string(),
                ],
            ).await
    }

    pub async fn insert_mempool_tx(&self, tx: Vec<u8>) -> Result<u64, Error> {
        self.client
            .execute("INSERT INTO mempool_txs (tx) VALUES ($1)", &[&tx])
            .await
    }

    pub async fn get_all_commitments(&self) -> Result<Vec<DbSequencerCommitment>, Error> {
        Ok(self
            .client
            .query("SELECT * FROM sequencer_commitments", &[])
            .await?
            .iter()
            .map(PostgresConnector::row_to_sequencer_commitment)
            .collect())
    }

    pub async fn get_all_txs(&self) -> Result<Vec<Vec<u8>>, Error> {
        Ok(self
            .client
            .query("SELECT * FROM mempool_txs", &[])
            .await?
            .iter()
            .map(|row| row.get("tx"))
            .collect())
    }

    pub async fn get_last_commitment(&self) -> Result<Option<DbSequencerCommitment>, Error> {
        let rows = self
            .client
            .query(
                "SELECT * FROM sequencer_commitments ORDER BY id DESC LIMIT 1",
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
    pub async fn create_table(&self, table: Tables) {
        let query = match table {
            Tables::SequencerCommitment => SEQUENCER_COMMITMENT_TABLE_CREATE_QUERY,
            Tables::MempoolTxs => MEMPOOL_TXS_TABLE_CREATE_QUERY,
        };
        self.client.execute(query, &[]).await.unwrap();
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
            status: CommitmentStatus::from_str(row.get("status")).unwrap(),
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
        client.create_table(Tables::SequencerCommitment).await;

        let inserted = client
            .insert_sequencer_commitment(
                3,
                4,
                vec![0; 32],
                vec![255; 32],
                vec![0; 32],
                10,
                11,
                vec![1; 32],
                CommitmentStatus::Mempool,
            )
            .await
            .unwrap();

        assert_eq!(inserted, 1);

        let rows = client.get_all_commitments().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].l1_tx_id, vec![0; 32]);
        assert_eq!(rows[0].l1_start_hash, vec![255; 32]);
        assert_eq!(rows[0].l1_end_hash, vec![0; 32]);
        assert_eq!(rows[0].l2_start_height, 10);
        assert_eq!(rows[0].l2_end_height, 11);
        assert!(matches!(rows[0].status, CommitmentStatus::Mempool));

        let _ = client.drop_table(Tables::SequencerCommitment).await;
    }

    #[tokio::test]
    async fn test_insert_rlp_tx() {
        let client = PostgresConnector::new_test_client().await.unwrap();
        client.create_table(Tables::MempoolTxs).await;

        client.insert_mempool_tx(vec![1, 2, 3]).await.unwrap();

        let txs = client.get_all_txs().await.unwrap();

        assert_eq!(txs.len(), 1);

        assert_eq!(txs[0], vec![1, 2, 3]);
    }
}
