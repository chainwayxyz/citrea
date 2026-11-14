//! Ledger DB migrations for data stored in Bitcoin DA encodings.

use std::sync::Arc;

use anyhow::Context;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use borsh::BorshDeserialize;
use sov_db::ledger_db::migrations::LedgerMigration;
use sov_db::ledger_db::LedgerDB;
use sov_db::schema::tables::ShortHeaderProofBySlotHash;
use sov_schema_db::SchemaBatch;
use tracing::info;

use crate::spec::header::HeaderWrapper;
use crate::spec::short_proof::BitcoinHeaderShortProof;

/// How many re-encoded proofs [`ReencodeShortHeaderProofs`] writes in one batch.
const REENCODE_BATCH_SIZE: usize = 10_000;

/// Rewrites the short header proofs v2.10 cached in the current encoding.
///
/// v2.10 encoded each coinbase field separately with Borsh, the witness as a `Vec<Vec<u8>>`,
/// which let its input, output or witness item counts amplify guest reads. The current codec
/// stores the whole consensus-encoded transaction in one Borsh byte vector, which the cached
/// proofs fail to decode as. Each proof is decoded the v2.10 way and written back, without
/// reading Bitcoin. Proofs that already decode are kept. One that decodes neither way fails the
/// migration.
pub struct ReencodeShortHeaderProofs;

impl LedgerMigration for ReencodeShortHeaderProofs {
    fn identifier(&self) -> (String, u64) {
        ("reencode_short_header_proofs".to_string(), 1)
    }

    fn execute(
        &self,
        ledger_db: Arc<LedgerDB>,
        _tables_to_drop: &mut Vec<String>,
    ) -> anyhow::Result<()> {
        let db = ledger_db.db_handle();
        let mut rows = db.iter::<ShortHeaderProofBySlotHash>()?;
        rows.seek_to_first();
        let mut batch = SchemaBatch::new();
        let mut batched = 0;
        let mut reencoded = 0;
        for row in rows {
            let row = row?;
            if BitcoinHeaderShortProof::try_from_slice(&row.value).is_ok() {
                continue;
            }
            let V2_10ShortHeaderProof(proof) = V2_10ShortHeaderProof::try_from_slice(&row.value)
                .with_context(|| {
                    format!(
                        "Cannot decode the short header proof of L1 block {}",
                        hex::encode(row.key)
                    )
                })?;
            batch.put::<ShortHeaderProofBySlotHash>(&row.key, &borsh::to_vec(&proof)?)?;
            batched += 1;
            reencoded += 1;
            // Each write is synced, so one per proof makes the migration slow
            if batched == REENCODE_BATCH_SIZE {
                db.write_schemas(std::mem::take(&mut batch))?;
                batched = 0;
            }
        }
        if batched > 0 {
            db.write_schemas(batch)?;
        }
        info!("Re-encoded {reencoded} short header proofs cached by v2.10");
        Ok(())
    }
}

/// A short header proof in the v2.10 encoding. This is a copy, not the current codec, so it keeps
/// decoding what v2.10 stored when the current encoding changes.
struct V2_10ShortHeaderProof(BitcoinHeaderShortProof);

impl BorshDeserialize for V2_10ShortHeaderProof {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let header = HeaderWrapper::deserialize_reader(reader)?;
        let coinbase_tx = deserialize_v2_10_tx(reader)?;
        let coinbase_tx_txid_merkle_proof = Vec::<[u8; 32]>::deserialize_reader(reader)?;
        Ok(Self(BitcoinHeaderShortProof::new(
            header,
            coinbase_tx.into(),
            coinbase_tx_txid_merkle_proof,
        )))
    }
}

fn deserialize_v2_10_tx<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Transaction> {
    let version = Version(i32::deserialize_reader(reader)?);
    let lock_time = LockTime::from_consensus(u32::deserialize_reader(reader)?);
    let input = (0..usize::deserialize_reader(reader)?)
        .map(|_| {
            Ok(TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array(<[u8; 32]>::deserialize_reader(reader)?),
                    vout: u32::deserialize_reader(reader)?,
                },
                script_sig: ScriptBuf::from_bytes(Vec::<u8>::deserialize_reader(reader)?),
                sequence: Sequence(u32::deserialize_reader(reader)?),
                witness: Witness::from(Vec::<Vec<u8>>::deserialize_reader(reader)?),
            })
        })
        .collect::<borsh::io::Result<_>>()?;
    let output = (0..usize::deserialize_reader(reader)?)
        .map(|_| {
            Ok(TxOut {
                value: Amount::from_sat(u64::deserialize_reader(reader)?),
                script_pubkey: ScriptBuf::from_bytes(Vec::<u8>::deserialize_reader(reader)?),
            })
        })
        .collect::<borsh::io::Result<_>>()?;
    Ok(Transaction {
        version,
        lock_time,
        input,
        output,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use sov_db::ledger_db::migrations::{LedgerDBMigrator, Migrations};
    use sov_db::ledger_db::SharedLedgerOps;
    use sov_db::rocks_db_config::RocksdbConfig;
    use sov_db::schema::tables::FULL_NODE_LEDGER_TABLES;
    use sov_rollup_interface::services::da::DaService;

    use super::*;
    use crate::service::{calculate_witness_root, BitcoinService};
    use crate::spec::block::BitcoinBlock;

    fn migrations() -> Migrations {
        static MIGRATIONS: OnceLock<Vec<Box<dyn LedgerMigration + Send + Sync>>> = OnceLock::new();
        MIGRATIONS.get_or_init(|| vec![Box::new(ReencodeShortHeaderProofs)])
    }

    struct EncodedProofs {
        v2_10: Vec<u8>,
        current: Vec<u8>,
    }

    /// The proof v2.10 cached, and the proof rebuilt from the block as
    /// `get_block_by_hash` and `block_to_short_header_proof` would.
    fn fixtures() -> Vec<EncodedProofs> {
        let json: serde_json::Value =
            serde_json::from_str(include_str!("../test_data/legacy_short_header_proofs.json"))
                .unwrap();
        json["blocks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                let hex_field = |key: &str| hex::decode(entry[key].as_str().unwrap()).unwrap();
                let block: bitcoin::Block =
                    bitcoin::consensus::deserialize(&hex_field("block")).unwrap();
                let txdata: Vec<_> = block.txdata.into_iter().map(Into::into).collect();
                let header = HeaderWrapper::new(
                    block.header,
                    txdata.len() as u32,
                    entry["height"].as_u64().unwrap(),
                    calculate_witness_root(&txdata, txdata.len()),
                );
                let proof =
                    BitcoinService::block_to_short_header_proof(BitcoinBlock { header, txdata });
                EncodedProofs {
                    v2_10: hex_field("legacy_shp"),
                    current: borsh::to_vec(&proof).unwrap(),
                }
            })
            .collect()
    }

    fn migrate(path: &std::path::Path, tables: &[String]) -> anyhow::Result<()> {
        LedgerDBMigrator::new(path, migrations()).migrate(None, tables.to_vec())
    }

    #[test]
    fn reencodes_v2_10_proofs_as_a_refetch_would() {
        let directory = tempfile::tempdir().unwrap();
        let tables: Vec<_> = FULL_NODE_LEDGER_TABLES
            .iter()
            .map(ToString::to_string)
            .collect();
        let open = || {
            LedgerDB::with_config(&RocksdbConfig::new(
                directory.path(),
                None,
                Some(tables.clone()),
            ))
            .unwrap()
        };

        let fixtures = fixtures();
        let ledger_db = open();
        let mut expected = vec![];
        for (fixture_index, fixture) in fixtures.iter().enumerate() {
            let error = BitcoinHeaderShortProof::try_from_slice(&fixture.v2_10).unwrap_err();
            assert!(error
                .to_string()
                .contains("invalid transaction consensus encoding"));
            // Each block is cached once by v2.10 and once already in the current encoding
            for (encoding_index, stored) in
                [&fixture.v2_10, &fixture.current].into_iter().enumerate()
            {
                let mut key = [0; 32];
                key[0] = fixture_index as u8;
                key[1] = encoding_index as u8;
                ledger_db
                    .put_short_header_proof_by_l1_hash(&key, stored.clone())
                    .unwrap();
                expected.push((key, fixture.current.clone()));
            }
        }
        drop(ledger_db);

        migrate(directory.path(), &tables).unwrap();
        let ledger_db = open();
        for (hash, current) in expected {
            assert_eq!(
                ledger_db.get_short_header_proof_by_l1_hash(&hash).unwrap(),
                Some(current)
            );
        }
        assert!(ledger_db
            .get_executed_migrations()
            .unwrap()
            .contains(&ReencodeShortHeaderProofs.identifier()));
    }

    #[test]
    fn unreadable_proof_fails_the_migration() {
        let directory = tempfile::tempdir().unwrap();
        let tables: Vec<_> = FULL_NODE_LEDGER_TABLES
            .iter()
            .map(ToString::to_string)
            .collect();
        let ledger_db = LedgerDB::with_config(&RocksdbConfig::new(
            directory.path(),
            None,
            Some(tables.clone()),
        ))
        .unwrap();
        ledger_db
            .put_short_header_proof_by_l1_hash(&[7; 32], b"unreadable".to_vec())
            .unwrap();
        drop(ledger_db);

        let error = migrate(directory.path(), &tables).unwrap_err();
        assert!(format!("{error:#}").contains(&hex::encode([7; 32])));
    }
}
