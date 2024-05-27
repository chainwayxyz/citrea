use std::str::FromStr;

use deadpool_postgres::tokio_postgres::config::Config as PgConfig;
use deadpool_postgres::tokio_postgres::{NoTls, Row};
use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, PoolError, RecyclingMethod};
use sov_rollup_interface::rpc::StateTransitionRpcResponse;
use tracing::{debug, instrument};

use crate::config::SharedBackupDbConfig;
use crate::tables::{
    CommitmentStatus, DbMempoolTx, DbProof, DbSequencerCommitment, ProofType, Tables,
    INDEX_L1_END_HASH, INDEX_L1_END_HEIGHT, INDEX_L2_END_HEIGHT, MEMPOOL_TXS_TABLE_CREATE_QUERY,
    PROOF_TABLE_CREATE_QUERY, SEQUENCER_COMMITMENT_TABLE_CREATE_QUERY,
};

#[derive(Clone)]
pub struct PostgresConnector {
    client: Pool,
}

impl PostgresConnector {
    #[instrument(level = "trace", err)]
    pub async fn new(pg_config: SharedBackupDbConfig) -> Result<Self, PoolError> {
        let mut cfg: PgConfig = pg_config.clone().into();

        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let mgr = Manager::from_config(cfg.clone(), NoTls, mgr_config.clone());
        let mut pool = Pool::builder(mgr)
            .max_size(pg_config.max_pool_size().unwrap_or(16))
            .build()
            .unwrap();
        let mut client = pool.get().await?;

        debug!("Connecting PG client to DB: {}", pg_config.db_name());

        // Create new db if running thread is not main or tokio-runtime-worker, meaning when running for tests
        if cfg!(feature = "test-utils") {
            // create new db
            let _ = client
                .batch_execute(&format!("CREATE DATABASE {};", pg_config.db_name()))
                .await;

            //connect to new db
            cfg.dbname(pg_config.db_name());
            let mgr = Manager::from_config(cfg, NoTls, mgr_config);
            pool = Pool::builder(mgr)
                .max_size(pg_config.max_pool_size().unwrap_or(16))
                .build()
                .unwrap();
            // new client
            client = pool.get().await?;
        }

        // create tables
        client
            .batch_execute(SEQUENCER_COMMITMENT_TABLE_CREATE_QUERY)
            .await?;
        client.batch_execute(MEMPOOL_TXS_TABLE_CREATE_QUERY).await?;
        client.batch_execute(PROOF_TABLE_CREATE_QUERY).await?;
        let db_client = Self { client: pool };

        let _ = db_client.create_indexes().await;

        Ok(db_client)
    }

    #[instrument(level = "trace", skip(self), err)]
    pub async fn client(&self) -> Result<Object, PoolError> {
        self.client.get().await
    }

    #[instrument(level = "trace", skip(self), err, ret)]
    pub async fn create_indexes(&self) -> Result<(), PoolError> {
        let client = self.client().await?;
        client.batch_execute(INDEX_L1_END_HEIGHT).await?;
        client.batch_execute(INDEX_L1_END_HASH).await?;
        client.batch_execute(INDEX_L2_END_HEIGHT).await?;
        Ok(())
    }

    #[cfg(feature = "test-utils")]
    pub async fn new_test_client(db_name: String) -> Result<Self, PoolError> {
        let mut cfg: PgConfig = SharedBackupDbConfig::default().into();

        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let mgr = Manager::from_config(cfg.clone(), NoTls, mgr_config.clone());
        let pool = Pool::builder(mgr).max_size(16).build().unwrap();
        let client = pool.get().await.unwrap();

        client
            .batch_execute(&format!("DROP DATABASE IF EXISTS {};", db_name.clone()))
            .await
            .unwrap();

        client
            .batch_execute(&format!("CREATE DATABASE {};", db_name.clone()))
            .await
            .unwrap();

        drop(pool);

        //connect to new db
        cfg.dbname(db_name.as_str());
        let mgr = Manager::from_config(cfg, NoTls, mgr_config);
        let test_pool = Pool::builder(mgr).max_size(16).build().unwrap();
        let test_client = test_pool.get().await.unwrap();

        test_client
            .batch_execute(SEQUENCER_COMMITMENT_TABLE_CREATE_QUERY)
            .await
            .unwrap();

        test_client
            .batch_execute(MEMPOOL_TXS_TABLE_CREATE_QUERY)
            .await
            .unwrap();
        test_client
            .batch_execute(PROOF_TABLE_CREATE_QUERY)
            .await
            .unwrap();

        let test_client = Self { client: test_pool };

        test_client.create_indexes().await.unwrap();
        Ok(test_client)
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(level = "trace", skip_all, fields(l1_start_height), err, ret)]
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
    ) -> Result<u64, PoolError> {
        let client = self.client().await?;
        Ok(client
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
            ).await?)
    }

    #[instrument(level = "trace", skip(self, tx), err, ret)]
    pub async fn insert_mempool_tx(&self, tx_hash: Vec<u8>, tx: Vec<u8>) -> Result<u64, PoolError> {
        let client = self.client().await?;
        Ok(client
            .execute(
                "INSERT INTO mempool_txs (tx_hash, tx) VALUES ($1, $2);",
                &[&tx_hash, &tx],
            )
            .await?)
    }

    #[instrument(level = "trace", skip(self), err)]
    pub async fn get_all_commitments(&self) -> Result<Vec<DbSequencerCommitment>, PoolError> {
        let client = self.client().await?;
        Ok(client
            .query("SELECT * FROM sequencer_commitments", &[])
            .await?
            .iter()
            .map(PostgresConnector::row_to_sequencer_commitment)
            .collect())
    }

    #[instrument(level = "trace", skip(self), err)]
    pub async fn get_all_txs(&self) -> Result<Vec<DbMempoolTx>, PoolError> {
        let client = self.client().await?;
        Ok(client
            .query("SELECT * FROM mempool_txs", &[])
            .await?
            .iter()
            .map(PostgresConnector::row_to_mempool_tx)
            .collect())
    }

    #[instrument(level = "trace", skip(self), err)]
    pub async fn get_last_commitment(&self) -> Result<Option<DbSequencerCommitment>, PoolError> {
        let client = self.client().await?;
        let rows = client
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

    #[instrument(level = "trace", skip_all, err, ret)]
    pub async fn delete_txs_by_tx_hashes(&self, tx_hashes: Vec<Vec<u8>>) -> Result<u64, PoolError> {
        let client = self.client().await?;
        Ok(client
            .execute(
                "DELETE FROM mempool_txs WHERE tx_hash = ANY($1);",
                &[&tx_hashes],
            )
            .await?)
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(level = "trace", skip_all, fields(l1_tx_id), err, ret)]
    pub async fn insert_proof_data(
        &self,
        l1_tx_id: Vec<u8>,
        proof_data: Vec<u8>,
        state_transition_rpc_response: StateTransitionRpcResponse,
        proof_type: ProofType,
    ) -> Result<u64, PoolError> {
        let state_tranistion_rpc_response_json =
            postgres_types::Json::<StateTransitionRpcResponse>(state_transition_rpc_response);
        let client = self.client().await?;
        Ok(client
            .execute(
                "INSERT INTO proof (l1_tx_id, proof_data, state_transition, proof_type) VALUES ($1, $2, $3, $4);",
                &[&l1_tx_id, &proof_data, &state_tranistion_rpc_response_json, &proof_type.to_string()],
            )
            .await?)
    }

    #[instrument(level = "trace", skip(self), err)]
    pub async fn get_all_proof_data(&self) -> Result<Vec<DbProof>, PoolError> {
        let client = self.client().await?;
        Ok(client
            .query("SELECT * FROM proof", &[])
            .await?
            .iter()
            .map(PostgresConnector::row_to_proof)
            .collect())
    }

    #[instrument(level = "trace", skip(self), fields(%table), err, ret)]
    pub async fn drop_table(&self, table: Tables) -> Result<u64, PoolError> {
        let client = self.client().await?;
        Ok(client
            .execute(format!("DROP TABLE {};", table).as_str(), &[])
            .await?)
    }

    #[cfg(test)]
    #[instrument(level = "trace", skip(self), fields(%table), ret)]
    pub async fn create_table(&self, table: Tables) {
        let client = self.client().await.unwrap();
        let query = match table {
            Tables::SequencerCommitment => SEQUENCER_COMMITMENT_TABLE_CREATE_QUERY,
            Tables::MempoolTxs => MEMPOOL_TXS_TABLE_CREATE_QUERY,
            Tables::Proof => PROOF_TABLE_CREATE_QUERY,
        };
        client.execute(query, &[]).await.unwrap();
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

    fn row_to_mempool_tx(row: &Row) -> DbMempoolTx {
        DbMempoolTx {
            tx_hash: row.get("tx_hash"),
            tx: row.get("tx"),
        }
    }

    fn row_to_proof(row: &Row) -> DbProof {
        DbProof {
            l1_tx_id: row.get("l1_tx_id"),
            proof_data: row.get("proof_data"),
            state_transition: row.get("state_transition"),
            proof_type: ProofType::from_str(row.get("proof_type")).unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tables::Tables;

    #[tokio::test]
    async fn test_insert_sequencer_commitment() {
        let client = PostgresConnector::new_test_client("insert_sequencer_commitments".to_owned())
            .await
            .unwrap();
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
        let client = PostgresConnector::new_test_client("insert_rlp_tx".to_owned())
            .await
            .unwrap();
        client.create_table(Tables::MempoolTxs).await;

        client
            .insert_mempool_tx(vec![1, 2, 3], vec![1, 2, 4])
            .await
            .unwrap();

        let txs = client.get_all_txs().await.unwrap();

        assert_eq!(txs.len(), 1);
        assert_eq!(
            txs[0],
            DbMempoolTx {
                tx_hash: vec![1, 2, 3],
                tx: vec![1, 2, 4]
            }
        );

        client
            .insert_mempool_tx(vec![3, 4, 5], vec![10, 20, 42])
            .await
            .unwrap();

        client
            .insert_mempool_tx(vec![5, 6, 7], vec![12, 22, 42])
            .await
            .unwrap();

        client
            .delete_txs_by_tx_hashes(vec![vec![1, 2, 3], vec![5, 6, 7]])
            .await
            .unwrap();

        let txs = client.get_all_txs().await.unwrap();

        assert_eq!(txs.len(), 1);
        assert_eq!(
            txs[0],
            DbMempoolTx {
                tx_hash: vec![3, 4, 5],
                tx: vec![10, 20, 42]
            }
        );
    }

    #[tokio::test]
    async fn test_insert_proof_data() {
        let client = PostgresConnector::new_test_client("test_insert_proof_data".to_string())
            .await
            .unwrap();
        client.create_table(Tables::Proof).await;

        let inserted = client
            .insert_proof_data(
                vec![0; 32],
                vec![1; 32],
                StateTransitionRpcResponse {
                    initial_state_root: [0; 32].to_vec(),
                    final_state_root: [1; 32].to_vec(),
                    state_diff: vec![(vec![2u8; 32], Some(vec![3u8; 32])), (vec![5u8; 32], None)]
                        .into_iter()
                        .collect(),
                    da_slot_hash: [2; 32],
                    sequencer_public_key: [3; 32].to_vec(),
                    sequencer_da_public_key: [4; 32].to_vec(),
                    validity_condition: [5; 32].to_vec(),
                },
                ProofType::Full,
            )
            .await
            .unwrap();

        assert_eq!(inserted, 1);

        let proofs = client.get_all_proof_data().await.unwrap();
        assert_eq!(proofs.len(), 1);
        assert_eq!(
            proofs[0],
            DbProof {
                l1_tx_id: vec![0; 32],
                proof_data: vec![1; 32],
                state_transition: postgres_types::Json(StateTransitionRpcResponse {
                    initial_state_root: [0; 32].to_vec(),
                    final_state_root: [1; 32].to_vec(),
                    state_diff: vec![(vec![2; 32], Some(vec![3; 32])), (vec![5; 32], None)]
                        .into_iter()
                        .collect(),
                    da_slot_hash: [2; 32],
                    sequencer_public_key: [3; 32].to_vec(),
                    sequencer_da_public_key: [4; 32].to_vec(),
                    validity_condition: [5; 32].to_vec(),
                }),
                proof_type: ProofType::Full,
            }
        );

        client.drop_table(Tables::Proof).await.unwrap();
    }
}
