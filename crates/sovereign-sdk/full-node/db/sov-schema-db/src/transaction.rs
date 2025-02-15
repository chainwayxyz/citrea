//! Snapshot related logic
//!
use std::sync::{Arc, Mutex};

use crate::schema::{KeyCodec, KeyDecoder, ValueCodec};
use crate::schema_batch::SchemaBatchIterator;
use crate::{Operation, Schema, SchemaBatch, SchemaKey, SchemaValue, SeekKeyEncoder, DB};

/// Wrapper around [`DB`] which allows caching writes in memory.
#[derive(Debug)]
pub struct DbTransaction {
    cache: Mutex<SchemaBatch>,
    db: Arc<DB>,
}

impl DbTransaction {
    /// Create new [`DbTransaction`]
    pub fn new(db: Arc<DB>) -> Self {
        Self {
            cache: Mutex::new(SchemaBatch::default()),
            db,
        }
    }

    /// Store a value in transaction
    pub fn put<S: Schema>(
        &self,
        key: &impl KeyCodec<S>,
        value: &impl ValueCodec<S>,
    ) -> anyhow::Result<()> {
        self.cache
            .lock()
            .expect("Local SchemaBatch lock must not be poisoned")
            .put(key, value)
    }

    /// Delete given key from transaction
    pub fn delete<S: Schema>(&self, key: &impl KeyCodec<S>) -> anyhow::Result<()> {
        self.cache
            .lock()
            .expect("Local SchemaBatch lock must not be poisoned")
            .delete(key)
    }

    /// Writes many operations at once, atomically
    pub fn write_many(&self, batch: SchemaBatch) -> anyhow::Result<()> {
        let mut cache = self
            .cache
            .lock()
            .expect("Local SchemaBatch lock must not be poisoned");
        cache.merge(batch);
        Ok(())
    }

    /// Get a value from current transaction or underlying database
    pub fn read<S: Schema>(&self, key: &impl KeyCodec<S>) -> anyhow::Result<Option<S::Value>> {
        // Hold local cache lock explicitly, so reads are atomic
        let local_cache = self
            .cache
            .lock()
            .expect("SchemaBatch lock should not be poisoned");

        // 1. Check in cache
        if let Some(operation) = local_cache.read(key)? {
            return decode_operation::<S>(operation);
        }

        self.db.get(key)
    }

    /// Get value of largest key written value for given [`Schema`]
    pub fn get_largest<S: Schema>(&self) -> anyhow::Result<Option<(S::Key, S::Value)>> {
        let local_cache = self
            .cache
            .lock()
            .expect("SchemaBatch lock must not be poisoned");
        let local_cache_iter = local_cache.iter::<S>();

        let db_iter = self.db.raw_iter::<S>()?;

        let mut combined_iter: DbTransactionIter<'_, S, _, _> = DbTransactionIter {
            local_cache_iter: local_cache_iter.peekable(),
            db_iter: db_iter.peekable(),
        };

        if let Some((key, value)) = combined_iter.next() {
            let key = S::Key::decode_key(&key)?;
            let value = S::Value::decode_value(&value)?;
            return Ok(Some((key, value)));
        }

        Ok(None)
    }

    /// Get largest value in [`Schema`] that is smaller or equal than give `seek_key`
    pub fn get_prev<S: Schema>(
        &self,
        seek_key: &impl SeekKeyEncoder<S>,
    ) -> anyhow::Result<Option<(S::Key, S::Value)>> {
        let seek_key = seek_key.encode_seek_key()?;
        let local_cache = self
            .cache
            .lock()
            .expect("Local cache lock must not be poisoned");
        let local_cache_iter = local_cache.iter_range::<S>(seek_key.clone());

        let mut db_iter = self.db.raw_iter::<S>()?;
        db_iter.seek(seek_key).unwrap();

        let mut combined_iter: DbTransactionIter<'_, S, _, _> = DbTransactionIter {
            local_cache_iter: local_cache_iter.peekable(),
            db_iter: db_iter.peekable(),
        };

        if let Some((key, value)) = combined_iter.next() {
            let key = S::Key::decode_key(&key)?;
            let value = S::Value::decode_value(&value)?;
            return Ok(Some((key, value)));
        }
        Ok(None)
    }
}

impl From<DbTransaction> for SchemaBatch {
    fn from(value: DbTransaction) -> Self {
        value
            .cache
            .into_inner()
            .expect("Schema batch lock must not be poisoned")
    }
}

struct DbTransactionIter<'a, S, LocalIter, DbIter>
where
    S: Schema,
    LocalIter: Iterator<Item = (&'a SchemaKey, &'a Operation)>,
    DbIter: Iterator<Item = (SchemaKey, SchemaValue)>,
{
    local_cache_iter: std::iter::Peekable<SchemaBatchIterator<'a, S, LocalIter>>,
    db_iter: std::iter::Peekable<DbIter>,
}

impl<'a, S, LocalIter, DbIter> Iterator for DbTransactionIter<'a, S, LocalIter, DbIter>
where
    S: Schema,
    LocalIter: Iterator<Item = (&'a SchemaKey, &'a Operation)>,
    DbIter: Iterator<Item = (SchemaKey, SchemaValue)>,
{
    type Item = (SchemaKey, SchemaValue);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let local_cache_peeked = self.local_cache_iter.peek();
            let db_peeked = self.db_iter.peek();

            match (local_cache_peeked, db_peeked) {
                // Both iterators exhausted
                (None, None) => break,
                // Parent exhausted (just like me on friday)
                (Some(&(key, operation)), None) => {
                    self.local_cache_iter.next();
                    let next = put_or_none(key, operation);
                    if next.is_none() {
                        continue;
                    }
                    return next;
                }
                // Local exhausted
                (None, Some((_key, _value))) => {
                    return self.db_iter.next();
                }
                // Both are active, need to compare keys
                (Some(&(local_key, local_operation)), Some((db_key, _db_value))) => {
                    return if local_key < db_key {
                        self.db_iter.next()
                    } else {
                        // Local is preferable, as it is the latest
                        // But both operators must succeed
                        if local_key == db_key {
                            self.db_iter.next();
                        }
                        self.local_cache_iter.next();
                        let next = put_or_none(local_key, local_operation);
                        if next.is_none() {
                            continue;
                        }
                        next
                    };
                }
            }
        }

        None
    }
}

fn decode_operation<S: Schema>(operation: &Operation) -> anyhow::Result<Option<S::Value>> {
    match operation {
        Operation::Put { value } => {
            let value = S::Value::decode_value(value)?;
            Ok(Some(value))
        }
        Operation::Delete => Ok(None),
    }
}

fn put_or_none(key: &SchemaKey, operation: &Operation) -> Option<(SchemaKey, SchemaValue)> {
    if let Operation::Put { value } = operation {
        return Some((key.to_vec(), value.to_vec()));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::define_schema;
    use crate::schema::KeyEncoder;
    use crate::test::{TestCompositeField, TestField};

    define_schema!(TestSchema, TestCompositeField, TestField, "TestCF");

    fn encode_key(key: &TestCompositeField) -> Vec<u8> {
        <TestCompositeField as KeyEncoder<TestSchema>>::encode_key(key).unwrap()
    }

    fn encode_value(value: &TestField) -> Vec<u8> {
        <TestField as ValueCodec<TestSchema>>::encode_value(value).unwrap()
    }

    #[test]
    fn test_db_transaction_iterator_empty() {
        let local_cache = SchemaBatch::new();
        let db = DB::open_temp("iter-test", vec![TestSchema::COLUMN_FAMILY_NAME]);

        let local_cache_iter = local_cache.iter::<TestSchema>().peekable();
        let db_iter = db.raw_iter::<TestSchema>().unwrap().peekable();

        let transaction_iter = DbTransactionIter::<'_, TestSchema, _, _> {
            local_cache_iter,
            db_iter,
        };

        let values: Vec<(SchemaKey, SchemaValue)> = transaction_iter.collect();

        assert!(values.is_empty());
    }

    #[test]
    fn test_db_transaction_iterator_values() {
        let k1 = TestCompositeField(0, 1, 0);
        let k2 = TestCompositeField(0, 1, 2);
        let k3 = TestCompositeField(3, 1, 0);
        let k4 = TestCompositeField(3, 2, 0);

        let mut db_values = SchemaBatch::new();
        db_values.put::<TestSchema>(&k2, &TestField(2)).unwrap();
        db_values.put::<TestSchema>(&k1, &TestField(1)).unwrap();
        db_values.put::<TestSchema>(&k4, &TestField(4)).unwrap();
        db_values.put::<TestSchema>(&k3, &TestField(3)).unwrap();

        let mut local_cache = SchemaBatch::new();
        local_cache.delete::<TestSchema>(&k3).unwrap();
        local_cache.put::<TestSchema>(&k1, &TestField(10)).unwrap();
        local_cache.put::<TestSchema>(&k2, &TestField(20)).unwrap();

        let db = DB::open_temp("iter-test", vec![TestSchema::COLUMN_FAMILY_NAME]);
        db.write_schemas(db_values).unwrap();

        let local_cache_iter = local_cache.iter::<TestSchema>().peekable();
        let db_iter = db.raw_iter::<TestSchema>().unwrap().peekable();

        let transaction_iter = DbTransactionIter::<'_, TestSchema, _, _> {
            local_cache_iter,
            db_iter,
        };

        let actual_values: Vec<(SchemaKey, SchemaValue)> = transaction_iter.collect();
        let expected_values = vec![
            (encode_key(&k4), encode_value(&TestField(4))),
            (encode_key(&k2), encode_value(&TestField(20))),
            (encode_key(&k1), encode_value(&TestField(10))),
        ];

        assert_eq!(expected_values, actual_values);
    }
}
