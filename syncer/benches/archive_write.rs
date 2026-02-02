//! Benchmark for measuring syncer archive write performance with different configurations.
//!
//! Run with:
//! ```
//! cargo bench --package summit-syncer --bench archive_write
//! ```

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write, varint::UInt};
use commonware_consensus::marshal::store::Blocks;
use commonware_consensus::types::Height;
use commonware_cryptography::sha256::{Digest as Sha256Digest, Sha256};
use commonware_cryptography::{Committable, Digest, Digestible, Hasher as _};
use commonware_runtime::buffer::PoolRef;
use commonware_runtime::{Metrics, Runner as _, tokio::Runner};
use commonware_storage::archive::{Archive as _, immutable};
use commonware_utils::{NZU64, NZUsize};
use std::num::{NonZeroU16, NonZeroU64};
use std::time::Instant;

type D = Sha256Digest;

const PAGE_SIZE: NonZeroU16 = NonZeroU16::new(1024).unwrap();
const PAGE_CACHE_SIZE: std::num::NonZeroUsize = NZUsize!(10);

// ============================================================================
// Inline Block type (avoid dependency on test-mocks feature)
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
struct Block<Dg: Digest> {
    parent: Dg,
    height: Height,
    timestamp: u64,
    digest: Dg,
}

impl<Dg: Digest> Block<Dg> {
    fn compute_digest<H: commonware_cryptography::Hasher<Digest = Dg>>(
        parent: &Dg,
        height: Height,
        timestamp: u64,
    ) -> Dg {
        let mut hasher = H::new();
        hasher.update(parent);
        hasher.update(&height.get().to_be_bytes());
        hasher.update(&timestamp.to_be_bytes());
        hasher.finalize()
    }

    fn new<H: commonware_cryptography::Hasher<Digest = Dg>>(
        parent: Dg,
        height: Height,
        timestamp: u64,
    ) -> Self {
        let digest = Self::compute_digest::<H>(&parent, height, timestamp);
        Self {
            parent,
            height,
            timestamp,
            digest,
        }
    }
}

impl<Dg: Digest> Write for Block<Dg> {
    fn write(&self, writer: &mut impl BufMut) {
        self.parent.write(writer);
        self.height.write(writer);
        UInt(self.timestamp).write(writer);
        self.digest.write(writer);
    }
}

impl<Dg: Digest> Read for Block<Dg> {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        let parent = Dg::read(reader)?;
        let height = Height::read(reader)?;
        let timestamp = UInt::read(reader)?.into();
        let digest = Dg::read(reader)?;
        Ok(Self {
            parent,
            height,
            timestamp,
            digest,
        })
    }
}

impl<Dg: Digest> EncodeSize for Block<Dg> {
    fn encode_size(&self) -> usize {
        self.parent.encode_size()
            + self.height.encode_size()
            + UInt(self.timestamp).encode_size()
            + self.digest.encode_size()
    }
}

impl<Dg: Digest> Digestible for Block<Dg> {
    type Digest = Dg;
    fn digest(&self) -> Dg {
        self.digest
    }
}

impl<Dg: Digest> Committable for Block<Dg> {
    type Commitment = Dg;
    fn commitment(&self) -> Dg {
        self.digest
    }
}

impl<Dg: Digest> commonware_consensus::Heightable for Block<Dg> {
    fn height(&self) -> Height {
        self.height
    }
}

impl<Dg: Digest> commonware_consensus::Block for Block<Dg> {
    fn parent(&self) -> Self::Commitment {
        self.parent
    }
}

// ============================================================================
// Benchmark
// ============================================================================

type B = Block<D>;

struct BenchConfig {
    name: &'static str,
    items_per_section: NonZeroU64,
    freezer_table_initial_size: u32,
    freezer_table_resize_frequency: u8,
    freezer_table_resize_chunk_size: u32,
}

fn run_benchmark_once(config: &BenchConfig, num_blocks: u64) -> (f64, f64, f64, f64) {
    let storage_dir = std::env::temp_dir().join(format!(
        "summit_syncer_bench_{}_{}",
        config.name.replace(" ", "_"),
        std::process::id()
    ));
    let cfg = commonware_runtime::tokio::Config::default().with_storage_directory(&storage_dir);
    let executor = Runner::new(cfg);

    let result = executor.start(|context| async move {
        let partition_prefix = format!("bench-{}", config.name.replace(" ", "-"));
        let buffer_pool = PoolRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);

        let mut finalized_blocks: immutable::Archive<_, D, B> = immutable::Archive::init(
            context.with_label("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!("{}-finalized_blocks-metadata", partition_prefix),
                freezer_table_partition: format!(
                    "{}-finalized_blocks-freezer-table",
                    partition_prefix
                ),
                freezer_table_initial_size: config.freezer_table_initial_size,
                freezer_table_resize_frequency: config.freezer_table_resize_frequency,
                freezer_table_resize_chunk_size: config.freezer_table_resize_chunk_size,
                freezer_key_partition: format!("{}-finalized_blocks-freezer-key", partition_prefix),
                freezer_key_buffer_pool: buffer_pool.clone(),
                freezer_value_partition: format!(
                    "{}-finalized_blocks-freezer-value",
                    partition_prefix
                ),
                freezer_value_target_size: 1024,
                freezer_value_compression: None,
                ordinal_partition: format!("{}-finalized_blocks-ordinal", partition_prefix),
                items_per_section: config.items_per_section,
                codec_config: (),
                replay_buffer: NZUsize!(1024),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");

        let mut block_write_times: Vec<(u64, u128)> = Vec::new();

        let mut parent = Sha256::hash(b"");
        for height in 1..=num_blocks {
            let block = B::new::<Sha256>(parent, Height::new(height), height);
            let commitment = block.commitment();
            parent = commitment;

            let start = Instant::now();
            Blocks::put(&mut finalized_blocks, block)
                .await
                .expect("failed to store finalized block");
            finalized_blocks
                .sync()
                .await
                .expect("failed to sync finalized block");
            let block_duration = start.elapsed().as_micros();
            block_write_times.push((height, block_duration));
        }

        // Calculate statistics
        let first_1000_avg: f64 = block_write_times
            .iter()
            .take(1000)
            .map(|(_, t)| *t)
            .sum::<u128>() as f64
            / 1000.0;
        let last_1000_avg: f64 = block_write_times
            .iter()
            .rev()
            .take(1000)
            .map(|(_, t)| *t)
            .sum::<u128>() as f64
            / 1000.0;

        let change_pct = ((last_1000_avg - first_1000_avg) / first_1000_avg) * 100.0;
        let avg = block_write_times.iter().map(|(_, t)| *t).sum::<u128>() as f64
            / block_write_times.len() as f64;

        (avg, change_pct, first_1000_avg, last_1000_avg)
    });

    let _ = std::fs::remove_dir_all(&storage_dir);
    result
}

fn run_benchmark(config: &BenchConfig, num_blocks: u64, iterations: usize) -> (f64, f64, f64, f64) {
    let mut avgs = Vec::new();
    let mut degradations = Vec::new();
    let mut first_1000s = Vec::new();
    let mut last_1000s = Vec::new();

    for _ in 0..iterations {
        let (avg, degradation, first_1000, last_1000) = run_benchmark_once(config, num_blocks);
        avgs.push(avg);
        degradations.push(degradation);
        first_1000s.push(first_1000);
        last_1000s.push(last_1000);
    }

    let avg_avg = avgs.iter().sum::<f64>() / avgs.len() as f64;
    let avg_degradation = degradations.iter().sum::<f64>() / degradations.len() as f64;
    let avg_first_1000 = first_1000s.iter().sum::<f64>() / first_1000s.len() as f64;
    let avg_last_1000 = last_1000s.iter().sum::<f64>() / last_1000s.len() as f64;

    (avg_avg, avg_degradation, avg_first_1000, avg_last_1000)
}

fn main() {
    let num_blocks = 1_000_000;
    let iterations = 1;

    println!("Syncer Archive Write Benchmark");
    println!("==============================");
    println!("Blocks: {}, Iterations: {}", num_blocks, iterations);
    println!();

    let config = BenchConfig {
        name: "marshal",
        items_per_section: NZU64!(10),
        freezer_table_initial_size: 64,
        freezer_table_resize_frequency: 10,
        freezer_table_resize_chunk_size: 10,
    };

    print!("Testing ({} iters)...", iterations);
    std::io::Write::flush(&mut std::io::stdout()).unwrap();

    let (avg, change_pct, first_1000, last_1000) = run_benchmark(&config, num_blocks, iterations);

    println!("\r                         ");
    println!("Results:");
    println!("  First 1000 blocks avg: {:.1} µs", first_1000);
    println!("  Last 1000 blocks avg:  {:.1} µs", last_1000);
    println!("  Overall avg:           {:.1} µs", avg);
    println!("  Degradation:           {:.1}%", change_pct);
}
