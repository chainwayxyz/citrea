extern crate criterion;

use alloy_consensus::constants::EMPTY_WITHDRAWALS;
use alloy_consensus::EMPTY_OMMER_ROOT_HASH;
use alloy_eips::eip7685::EMPTY_REQUESTS_HASH;
use alloy_primitives::{Address, Bloom, Bytes, Sealable, B256, B64, U256};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use reth_primitives::Header;

fn create_header(number: u64, gas_used: u64, tx_count: usize, extra_data_size: usize) -> Header {
    let mut transactions_root = [0u8; 32];
    transactions_root[0] = tx_count as u8;

    Header {
        parent_hash: B256::random(),
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: Address::random(),
        state_root: B256::random(),
        transactions_root: B256::from(transactions_root),
        receipts_root: B256::random(),
        withdrawals_root: Some(EMPTY_WITHDRAWALS),
        logs_bloom: Bloom::default(),
        difficulty: U256::ZERO,
        number,
        gas_limit: 30_000_000,
        gas_used,
        timestamp: 1234567890,
        mix_hash: B256::ZERO,
        nonce: B64::ZERO,
        base_fee_per_gas: Some(1_000_000_000),
        extra_data: Bytes::from(vec![0x42u8; extra_data_size]),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
        parent_beacon_block_root: Some(B256::ZERO),
        requests_hash: Some(EMPTY_REQUESTS_HASH),
    }
}

fn bench_seal_slow_empty_block(c: &mut Criterion) {
    let header = create_header(1, 0, 0, 0);
    c.bench_function("seal_slow_empty_block", |b| {
        b.iter(|| black_box(header.clone().seal_slow()))
    });
}

fn bench_seal_slow_varying_tx_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("seal_slow_tx_count");

    for tx_count in [0, 10, 100, 500, 1000] {
        let header = create_header(1, 15_000_000, tx_count, 0);
        group.bench_with_input(BenchmarkId::from_parameter(tx_count), &header, |b, h| {
            b.iter(|| black_box(h.clone().seal_slow()))
        });
    }
    group.finish();
}

fn bench_seal_slow_varying_extra_data(c: &mut Criterion) {
    let mut group = c.benchmark_group("seal_slow_extra_data");

    for size in [0, 32, 64, 128, 256] {
        let header = create_header(1, 15_000_000, 100, size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &header, |b, h| {
            b.iter(|| black_box(h.clone().seal_slow()))
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_seal_slow_empty_block,
    bench_seal_slow_varying_tx_count,
    bench_seal_slow_varying_extra_data,
);
criterion_main!(benches);
