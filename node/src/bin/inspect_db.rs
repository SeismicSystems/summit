use anyhow::Result;
use clap::Parser;
use commonware_runtime::buffer::PoolRef;
use commonware_runtime::{Metrics, Runner, tokio};
use commonware_storage::archive::{Archive as _, Identifier as ArchiveID, immutable};
use commonware_storage::metadata::{self, Metadata};
use commonware_utils::sequence::U64;
use std::num::NonZero;
use summit_types::{Block, Digest, utils::get_expanded_path};
use tracing::info;

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
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Expand store path
    let store_path_expanded = get_expanded_path(&args.store_path)?;

    info!("Opening database at: {:?}", store_path_expanded);
    info!("Database prefix: {}", args.db_prefix);
    info!("");

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

    executor.start(move |context| async move {
        // Create a buffer pool for the archives
        let buffer_pool = PoolRef::new(
            NonZero::new(4096).unwrap(),  // page size
            NonZero::new(8192).unwrap(),  // capacity
        );

        // Open the finalized_blocks archive
        info!("Opening finalized_blocks archive...");
        let finalized_blocks = immutable::Archive::<tokio::Context, Digest, Block>::init(
            context.with_label("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!("{}-finalized_blocks-metadata", db_prefix),
                freezer_table_partition: format!("{}-finalized_blocks-freezer-table", db_prefix),
                freezer_table_initial_size: 0,
                freezer_table_resize_frequency: 0,
                freezer_table_resize_chunk_size: 0,
                freezer_journal_partition: format!("{}-finalized_blocks-freezer-journal", db_prefix),
                freezer_journal_target_size: 0,
                freezer_journal_compression: None,
                freezer_journal_buffer_pool: buffer_pool.clone(),
                ordinal_partition: format!("{}-finalized_blocks-ordinal", db_prefix),
                items_per_section: NonZero::new(1).unwrap(),
                codec_config: (),
                replay_buffer: NonZero::new(1).unwrap(),
                write_buffer: NonZero::new(1).unwrap(),
            },
        )
        .await
        .expect("failed to init finalized_blocks");

        // Open application metadata
        info!("Opening application_metadata...");
        let application_metadata = Metadata::<tokio::Context, U64, u64>::init(
            context.with_label("application_metadata"),
            metadata::Config {
                partition: format!("{}-application-metadata", db_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("failed to init application_metadata");

        info!("");
        info!("=== DATABASE OVERVIEW ===");
        info!("");

        // Get block ranges
        let block_ranges: Vec<_> = finalized_blocks.ranges().collect();

        if block_ranges.is_empty() {
            info!("finalized_blocks: EMPTY");
        } else {
            info!("finalized_blocks ranges:");
            for &(range_start, range_end) in &block_ranges {
                info!("  - blocks {}-{} ({} blocks)", range_start, range_end, range_end - range_start + 1);
            }
        }

        // Get application metadata
        info!("");
        info!("application_metadata:");
        let latest_height = application_metadata.get(&LATEST_KEY).expect("failed to get metadata");
        info!("  - latest processed height: {}", latest_height);

        // Determine scan range
        let (start_height, end_height) = if block_ranges.is_empty() {
            info!("");
            info!("No blocks to scan.");
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

        info!("");
        info!("=== SCANNING BLOCKS {}-{} ===", start_height, end_height);
        info!("");

        let mut missing_blocks = Vec::new();
        let mut block_count = 0;

        for height in start_height..=end_height {
            // Get block
            let block = finalized_blocks.get(ArchiveID::Index(height)).await.expect("failed to get block");

            let has_block = block.is_some();

            if !has_block {
                missing_blocks.push(height);
            }

            if show_details {
                if let Some(ref b) = block {
                    block_count += 1;
                    info!("Block {}", height);
                    info!("  Height: {}", b.height());
                    info!("  View: {}", b.view());
                    info!("  Epoch: {}", b.epoch());
                    info!("  Parent digest: {:?}", b.parent());
                    info!("  Block hash: {:?}", b.payload.payload_inner.payload_inner.block_hash);
                    info!("  Parent hash: {:?}", b.payload.payload_inner.payload_inner.parent_hash);
                    info!("  Timestamp: {}", b.payload.payload_inner.payload_inner.timestamp);
                    info!("  Gas used: {}", b.payload.payload_inner.payload_inner.gas_used);
                    info!("  Transactions: {}", b.payload.payload_inner.payload_inner.transactions.len());
                    info!("");
                } else {
                    info!("Block {}: MISSING", height);
                    info!("");
                }
            } else if has_block {
                block_count += 1;
            }
        }

        info!("");
        info!("=== SUMMARY ===");
        info!("");
        info!("Total blocks found: {}", block_count);
        info!("Total blocks scanned: {}", end_height - start_height + 1);

        if check_gaps || !missing_blocks.is_empty() {
            info!("");
            if missing_blocks.is_empty() {
                info!("✓ No missing blocks in range");
            } else {
                info!("✗ Missing blocks ({} total):", missing_blocks.len());

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
                        info!("  - block {}", start);
                    } else {
                        info!("  - blocks {}-{} ({} missing)", start, end, end - start + 1);
                    }
                }
            }
        }

        info!("");
    });

    Ok(())
}
