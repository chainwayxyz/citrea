extern crate criterion;

use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use jmt::storage::TreeWriter;
use jmt::{JellyfishMerkleTree, KeyHash};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sov_db::rocks_db_config::RocksdbConfig;
use sov_db::state_db::StateDB;

fn generate_random_bytes(count: usize, size: usize) -> Vec<Vec<u8>> {
    let seed: [u8; 32] = [1; 32];
    let mut rng = StdRng::from_seed(seed);
    (0..count)
        .map(|_| (0..size).map(|_| rng.gen::<u8>()).collect())
        .collect()
}

fn prepare_state_db(size: usize) -> (StateDB, tempfile::TempDir, Vec<Vec<u8>>) {
    let tmpdir = tempfile::tempdir().unwrap();
    let raw_db = StateDB::setup_schema_db(&RocksdbConfig::new(tmpdir.path(), None, None)).unwrap();
    let db = StateDB::new(Arc::new(raw_db));

    let keys = generate_random_bytes(size, 32);
    let values = generate_random_bytes(size, 64);

    let mut key_preimages = Vec::with_capacity(size);
    let mut batch = Vec::with_capacity(size);

    for (key, value) in keys.iter().zip(values.iter()) {
        let key_hash = KeyHash::with::<sha2::Sha256>(&key);
        key_preimages.push((key_hash, key.as_slice()));
        batch.push((key_hash, Some(value.clone())));
    }

    let jmt = JellyfishMerkleTree::<_, sha2::Sha256>::new(&db);
    let (_root, _proof, tree_update) = jmt.put_value_set_with_proof(batch, 1).unwrap();

    db.put_preimages(key_preimages).unwrap();
    db.write_node_batch(&tree_update.node_batch).unwrap();

    (db, tmpdir, keys)
}

fn bench_single_read(c: &mut Criterion) {
    let test_data: Vec<_> = [100, 1000, 10_000]
        .iter()
        .map(|&size| {
            let (db, tmpdir, keys) = prepare_state_db(size);
            let key = keys[size / 2].clone();
            (size, db, tmpdir, key)
        })
        .collect();

    let mut group = c.benchmark_group("single_read");

    for (size, db, _tmpdir, key) in test_data {
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter(|| black_box(db.get_value_option_by_key(1, &key).unwrap()))
        });
    }
    group.finish();
}

fn bench_sequential_reads(c: &mut Criterion) {
    let test_data: Vec<_> = [10, 100]
        .iter()
        .map(|&size| {
            let (db, tmpdir, keys) = prepare_state_db(size);
            (size, db, tmpdir, keys)
        })
        .collect();

    let mut group = c.benchmark_group("sequential_reads");

    for (size, db, _tmpdir, keys) in test_data {
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter(|| {
                for key in &keys {
                    black_box(db.get_value_option_by_key(1, key).unwrap());
                }
            })
        });
    }
    group.finish();
}

fn bench_random_reads(c: &mut Criterion) {
    let test_data: Vec<_> = [100, 1000]
        .iter()
        .map(|&size| {
            let (db, tmpdir, keys) = prepare_state_db(size);
            let random_keys: Vec<_> = (0..100).map(|i| keys[(i * 17) % size].clone()).collect();
            (size, db, tmpdir, random_keys)
        })
        .collect();

    let mut group = c.benchmark_group("random_reads");

    for (size, db, _tmpdir, keys) in test_data {
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter(|| {
                for key in &keys {
                    black_box(db.get_value_option_by_key(1, key).unwrap());
                }
            })
        });
    }
    group.finish();
}

fn bench_miss_reads(c: &mut Criterion) {
    let test_data: Vec<_> = [100, 1000, 10_000]
        .iter()
        .map(|&size| {
            let (db, tmpdir, _) = prepare_state_db(size);
            (size, db, tmpdir)
        })
        .collect();

    let mut group = c.benchmark_group("miss_reads");
    let non_existent_key = vec![0xFFu8; 32];

    for (size, db, _tmpdir) in test_data {
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter(|| black_box(db.get_value_option_by_key(1, &non_existent_key).unwrap()))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_single_read,
    bench_sequential_reads,
    bench_random_reads,
    bench_miss_reads,
);
criterion_main!(benches);
