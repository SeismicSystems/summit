use anyhow::Result;
use clap::Parser;
use commonware_runtime::buffer::PoolRef;
use commonware_runtime::{Metrics, Runner, tokio};
use commonware_storage::archive::{Archive as _, Identifier as ArchiveID, immutable};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::sequence::U64;
use std::num::NonZero;
use summit_types::{Block, Digest, utils::get_expanded_path};

/// Key used in metadata store to track the latest processed block height
const LATEST_KEY: U64 = U64::new(0xFF);

/// Inspects Summit's syncer database archives
#[derive(Parser, Debug)]
#[command(name = "Inspect Database", version = "1.0")]
struct Args {
    /// Path to Summit's store directory
    #[arg(short, long, default_value = "/persistent/summit/store")]
    store_path: String,

    /// Database prefix used by Summit
    #[arg(short = 'p', long, default_value = "quartz")]
    db_prefix: String,

    /// Start block height (defaults to first available)
    #[arg(short, long)]
    from_block: Option<u64>,

    /// End block height (defaults to last available)
    #[arg(short, long)]
    to_block: Option<u64>,

    /// Show detailed information for each block
    #[arg(short, long)]
    details: bool,

    /// Check for gaps in the block sequence
    #[arg(short, long)]
    gaps: bool,

    /// Only show overview, skip block scanning
    #[arg(long)]
    overview_only: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Expand store path
    let store_path_expanded = get_expanded_path(&args.store_path)?;

    println!("Opening database at: {:?}", store_path_expanded);
    println!("Database prefix: {}", args.db_prefix);
    println!();
    println!("Looking for partitions:");
    println!("  - {}-finalized_blocks-metadata", args.db_prefix);
    println!("  - {}-finalized_blocks-freezer-table", args.db_prefix);
    println!("  - {}-finalized_blocks-freezer-journal", args.db_prefix);
    println!("  - {}-finalized_blocks-ordinal", args.db_prefix);
    println!();

    // Initialize runtime with storage directory
    let cfg = tokio::Config::default()
        .with_worker_threads(2)
        .with_storage_directory(store_path_expanded);
    let executor = tokio::Runner::new(cfg);

    let db_prefix = args.db_prefix.clone();
    let from_block = args.from_block;
    let to_block = args.to_block;
    let show_details = args.details;
    let check_gaps = args.gaps;
    let overview_only = args.overview_only;

    executor.start(move |context| async move {
        // Create a buffer pool for the archives
        // Larger buffers = better read performance for sequential scans
        let buffer_pool = PoolRef::new(
            NonZero::new(65536).unwrap(),   // 64KB pages for better I/O
            NonZero::new(131072).unwrap(),  // 8GB total cache (131072 * 64KB)
        );

        // Open the finalized_blocks archive
        // Use read-optimized settings: larger replay buffer for caching decompressed data
        println!("Opening finalized_blocks archive...");
        let finalized_blocks = immutable::Archive::<tokio::Context, Digest, Block>::init(
            context.with_label("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!("{}-finalized_blocks-metadata", db_prefix),
                freezer_table_partition: format!("{}-finalized_blocks-freezer-table", db_prefix),
                freezer_table_initial_size: 1, // Minimal - archive already exists
                freezer_table_resize_frequency: 0, // No resizing for read-only
                freezer_table_resize_chunk_size: 0, // No resizing for read-only
                freezer_journal_partition: format!("{}-finalized_blocks-freezer-journal", db_prefix),
                freezer_journal_target_size: 0, // No writes
                freezer_journal_compression: None, // Matches write config
                freezer_journal_buffer_pool: buffer_pool.clone(),
                ordinal_partition: format!("{}-finalized_blocks-ordinal", db_prefix),
                items_per_section: NonZero::new(262144).unwrap(), // Match production settings
                codec_config: (),
                replay_buffer: NonZero::new(256 * 1024 * 1024).unwrap(), // 256MB cache for decompressed data
                write_buffer: NonZero::new(1).unwrap(), // Minimal for read-only
            },
        )
        .await
        .expect("failed to init finalized_blocks");

        // Open application metadata
        println!("Opening application_metadata...");
        let application_metadata = Metadata::<tokio::Context, U64, u64>::init(
            context.with_label("application_metadata"),
            metadata::Config {
                partition: format!("{}-application-metadata", db_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("failed to init application_metadata");

        println!("");
        println!("=== DATABASE OVERVIEW ===");
        println!("");

        // Get block ranges
        let block_ranges: Vec<_> = finalized_blocks.ranges().collect();

        if block_ranges.is_empty() {
            println!("finalized_blocks: EMPTY");
        } else {
            println!("finalized_blocks ranges:");
            for &(range_start, range_end) in &block_ranges {
                println!("  - blocks {}-{} ({} blocks)", range_start, range_end, range_end - range_start + 1);
            }
        }

        // Get application metadata
        println!("");
        println!("application_metadata:");
        match application_metadata.get(&LATEST_KEY) {
            Some(height) => println!("  - latest processed height: {}", height),
            None => println!("  - latest processed height: NOT SET"),
        }

        // Skip scanning if overview_only flag is set
        if overview_only {
            println!("");
            println!("Overview complete (use --from-block and --to-block to scan specific ranges)");
            return;
        }

        // Determine scan range
        let (start_height, end_height) = if block_ranges.is_empty() {
            println!("");
            println!("No blocks to scan.");
            return;
        } else {
            let &(first_available, _) = block_ranges.first().unwrap();
            let &(_, last_available) = block_ranges.last().unwrap();

            let start = from_block.unwrap_or(first_available);
            let end = to_block.unwrap_or(last_available);

            if start > end {
                panic!("from-block ({}) cannot be greater than to-block ({})", start, end);
            }

            (start, end)
        };

        println!("");
        println!("=== SCANNING BLOCKS {}-{} ===", start_height, end_height);
        let total_to_scan = end_height - start_height + 1;
        println!("Total blocks to scan: {}", total_to_scan);
        println!("");

        let mut missing_blocks = Vec::new();
        let mut block_count = 0;
        let progress_interval = if total_to_scan > 1000 { 1000 } else { 100 };

        for height in start_height..=end_height {
            // Show progress for large scans
            if !show_details && (height - start_height) % progress_interval == 0 && height > start_height {
                println!("Progress: scanned {} / {} blocks...", height - start_height, total_to_scan);
            }

            // Only fetch and deserialize if we need details
            // Otherwise just check existence which should be faster
            if show_details {
                let block = finalized_blocks.get(ArchiveID::Index(height)).await.expect("failed to get block");

                if let Some(ref b) = block {
                    block_count += 1;
                    println!("Block {}", height);
                    println!("  Height: {}", b.height());
                    println!("  View: {}", b.view());
                    println!("  Epoch: {}", b.epoch());
                    println!("  Parent digest: {:?}", b.parent());
                    println!("  Block hash: {:?}", b.payload.payload_inner.payload_inner.block_hash);
                    println!("  Parent hash: {:?}", b.payload.payload_inner.payload_inner.parent_hash);
                    println!("  Timestamp: {}", b.payload.payload_inner.payload_inner.timestamp);
                    println!("  Gas used: {}", b.payload.payload_inner.payload_inner.gas_used);
                    println!("  Transactions: {}", b.payload.payload_inner.payload_inner.transactions.len());
                    println!("");
                } else {
                    missing_blocks.push(height);
                    println!("Block {}: MISSING", height);
                    println!("");
                }
            } else {
                // Fast path: just check existence
                let block = finalized_blocks.get(ArchiveID::Index(height)).await.expect("failed to get block");
                if block.is_some() {
                    block_count += 1;
                } else {
                    missing_blocks.push(height);
                }
            }
        }

        println!("");
        println!("=== SUMMARY ===");
        println!("");
        println!("Total blocks found: {}", block_count);
        println!("Total blocks scanned: {}", end_height - start_height + 1);

        if check_gaps || !missing_blocks.is_empty() {
            println!("");
            if missing_blocks.is_empty() {
                println!("✓ No missing blocks in range");
            } else {
                println!("✗ Missing blocks ({} total):", missing_blocks.len());

                // Group consecutive missing blocks into ranges
                let mut ranges = Vec::new();
                let mut range_start = missing_blocks[0];
                let mut range_end = missing_blocks[0];

                for &height in &missing_blocks[1..] {
                    if height == range_end + 1 {
                        range_end = height;
                    } else {
                        ranges.push((range_start, range_end));
                        range_start = height;
                        range_end = height;
                    }
                }
                ranges.push((range_start, range_end));

                for (start, end) in ranges {
                    if start == end {
                        println!("  - block {}", start);
                    } else {
                        println!("  - blocks {}-{} ({} missing)", start, end, end - start + 1);
                    }
                }
            }
        }

        println!("");
    });

    Ok(())
}
