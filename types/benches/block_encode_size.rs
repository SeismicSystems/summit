use alloy_primitives::Bytes as AlloyBytes;
use commonware_codec::EncodeSize;
use std::{hint::black_box, time::Instant};
use summit_types::Block;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

struct Case {
    name: &'static str,
    tx_count: usize,
    tx_size: usize,
    iterations: usize,
}

const CASES: &[Case] = &[
    Case {
        name: "1MiB_many_txs",
        tx_count: 1_024,
        tx_size: KIB,
        iterations: 20_000,
    },
    Case {
        name: "16MiB_many_txs",
        tx_count: 16 * 1_024,
        tx_size: KIB,
        iterations: 2_000,
    },
    Case {
        name: "64MiB_many_txs",
        tx_count: 64 * 1_024,
        tx_size: KIB,
        iterations: 500,
    },
    Case {
        name: "64MiB_large_txs",
        tx_count: 512,
        tx_size: 128 * KIB,
        iterations: 20_000,
    },
];

fn make_big_block(tx_count: usize, tx_size: usize) -> Block {
    let mut block = Block::genesis([7; 32]);
    let tx = AlloyBytes::from(vec![0x42; tx_size]);

    // Reuse the same immutable transaction bytes. This preserves encoded size
    // and transaction count while keeping benchmark setup memory reasonable.
    block.payload.payload_inner.payload_inner.transactions =
        (0..tx_count).map(|_| tx.clone()).collect();
    block
}

fn format_mib(bytes: usize) -> f64 {
    bytes as f64 / MIB as f64
}

fn main() {
    println!("Block encode_size() benchmark");
    println!("=============================");
    println!();
    println!(
        "{:<20} {:>10} {:>12} {:>12} {:>12} {:>12}",
        "case", "txs", "tx bytes", "block size", "iters", "ns/iter"
    );

    for case in CASES {
        let block = make_big_block(case.tx_count, case.tx_size);
        let block_size = block.encode_size();
        let tx_bytes = case.tx_count * case.tx_size;

        for _ in 0..100 {
            black_box(black_box(&block).encode_size());
        }

        let start = Instant::now();
        let mut total = 0usize;
        for _ in 0..case.iterations {
            total = total.wrapping_add(black_box(&block).encode_size());
        }
        let elapsed = start.elapsed();
        let nanos_per_iter = elapsed.as_nanos() as f64 / case.iterations as f64;

        black_box(total);

        println!(
            "{:<20} {:>10} {:>9.2}MiB {:>9.2}MiB {:>12} {:>12.2}",
            case.name,
            case.tx_count,
            format_mib(tx_bytes),
            format_mib(block_size),
            case.iterations,
            nanos_per_iter,
        );
    }
}
