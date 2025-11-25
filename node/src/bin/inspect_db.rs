use anyhow::Result;
use clap::Parser;
use commonware_runtime::buffer::PoolRef;
use commonware_runtime::{Metrics, Runner, tokio};
use commonware_storage::archive::{Archive as _, Identifier as ArchiveID, immutable};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::{fixed_bytes, sequence::{FixedBytes, U64}};
use std::num::NonZero;
use summit_types::{Block, Digest, utils::get_expanded_path};

/// Key used in metadata store to track the latest processed block height
const LATEST_KEY: U64 = U64::new(0xFF);

/// Key used in cache metadata to track cached epochs
const CACHED_EPOCHS_KEY: FixedBytes<1> = fixed_bytes!("0x00");

/// Inspects Summit's syncer database archives
#[derive(Parser, Debug)]
#[command(name = "Inspect Database", version = "1.0")]
struct Args {
    /// Path to Summit's store directory
    #[arg(short, long, default_value = "/persistent/summit/db")]
    store_path: String,

    /// Database prefix used by Summit
    #[arg(short = 'p', long, default_value = "quarts")]
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

    /// Show cache info (non-finalized blocks)
    #[arg(short = 'c', long)]
    show_cache: bool,
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
    let show_cache = args.show_cache;

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
                freezer_journal_compression: Some(3), // Match production compression level
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

        // Show cache info if requested
        if show_cache {
            println!("");
            println!("=== CACHE INFO (Non-Finalized Blocks) ===");
            println!("");

            // Open cache metadata
            let cache_metadata = Metadata::<tokio::Context, FixedBytes<1>, (u64, u64)>::init(
                context.with_label("cache_metadata"),
                metadata::Config {
                    partition: format!("{}-cache-metadata", db_prefix),
                    codec_config: ((), ()),
                },
            )
            .await;

            match cache_metadata {
                Ok(metadata) => {
                    match metadata.get(&CACHED_EPOCHS_KEY) {
                        Some(&(min_epoch, max_epoch)) => {
                            println!("Cached epochs: {} to {} ({} epochs)", min_epoch, max_epoch, max_epoch - min_epoch + 1);
                            println!("");
                            println!("Cache directories found:");
                            for epoch in min_epoch..=max_epoch {
                                println!("  - Epoch {}: {}-cache-cache-{}-*", epoch, db_prefix, epoch);
                            }
                        }
                        None => {
                            println!("No cached epochs metadata found");
                        }
                    }
                }
                Err(e) => {
                    println!("Could not open cache metadata: {}", e);
                }
            }
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
                match finalized_blocks.get(ArchiveID::Index(height)).await {
                    Ok(Some(ref b)) => {
                        block_count += 1;
                        println!("Block {}", height);
                        println!("  === Header Info ===");
                        println!("  Height: {}", b.header.height);
                        println!("  View: {}", b.header.view);
                        println!("  Epoch: {}", b.header.epoch);
                        println!("  Timestamp: {}", b.header.timestamp);
                        println!("  Parent digest: {:?}", b.header.parent);
                        println!("  Block digest: {:?}", b.header.digest);
                        println!("  Payload hash: {:?}", b.header.payload_hash);
                        println!("  Execution request hash: {:?}", b.header.execution_request_hash);
                        println!("  Checkpoint hash: {:?}", b.header.checkpoint_hash);
                        println!("  Prev epoch header hash: {:?}", b.header.prev_epoch_header_hash);
                        println!("  Block value: {}", b.header.block_value);
                        println!("  Added validators: {} ({:?})", b.header.added_validators.len(), b.header.added_validators);
                        println!("  Removed validators: {} ({:?})", b.header.removed_validators.len(), b.header.removed_validators);
                        println!("  === Ethereum Payload ===");
                        println!("  Block hash: {:?}", b.payload.payload_inner.payload_inner.block_hash);
                        println!("  Parent hash: {:?}", b.payload.payload_inner.payload_inner.parent_hash);
                        println!("  Fee recipient: {:?}", b.payload.payload_inner.payload_inner.fee_recipient);
                        println!("  State root: {:?}", b.payload.payload_inner.payload_inner.state_root);
                        println!("  Receipts root: {:?}", b.payload.payload_inner.payload_inner.receipts_root);
                        println!("  Gas limit: {}", b.payload.payload_inner.payload_inner.gas_limit);
                        println!("  Gas used: {}", b.payload.payload_inner.payload_inner.gas_used);
                        println!("  Base fee per gas: {}", b.payload.payload_inner.payload_inner.base_fee_per_gas);
                        println!("  Transactions: {}", b.payload.payload_inner.payload_inner.transactions.len());
                        println!("  Withdrawals: {}", b.payload.payload_inner.withdrawals.len());
                        println!("  Execution requests: {}", b.execution_requests.len());
                        println!("");
                    }
                    Ok(None) => {
                        missing_blocks.push(height);
                        println!("Block {}: MISSING", height);
                        println!("");
                    }
                    Err(e) => {
                        missing_blocks.push(height);
                        println!("Block {}: CORRUPTED ({})", height, e);
                        println!("");
                    }
                }
            } else {
                // Fast path: just check existence
                match finalized_blocks.get(ArchiveID::Index(height)).await {
                    Ok(Some(_)) => {
                        block_count += 1;
                    }
                    Ok(None) => {
                        missing_blocks.push(height);
                    }
                    Err(e) => {
                        missing_blocks.push(height);
                        if show_details {
                            println!("Block {}: CORRUPTED ({})", height, e);
                        }
                    }
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
