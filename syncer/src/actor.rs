use std::{collections::BTreeSet, num::NonZero, time::Duration};

use crate::{
    Orchestration, Orchestrator,
    coordinator::Coordinator,
    handler::Handler,
    ingress::{Mailbox, Message},
    key::{MultiIndex, Value},
};
use commonware_broadcast::{Broadcaster as _, buffered};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::Viewable as _;
use commonware_consensus::simplex::types::Finalization;
use commonware_macros::select;
use commonware_p2p::{Receiver, Recipients, Sender, utils::requester};
use commonware_resolver::{Resolver as _, p2p};
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};
use commonware_storage::{
    archive::{
        self, Archive as _, Identifier, immutable::Archive as ImmutableArchive,
        prunable::Archive as PrunableArchive,
    },
    translator::TwoCap,
};
use commonware_utils::NZU64;
use futures::{StreamExt as _, channel::mpsc};
use governor::Quota;
#[cfg(feature = "prom")]
use metrics::histogram;
use rand::Rng;
use summit_types::{Block, Digest, Finalized, Notarized, PublicKey, Signature};
use tracing::{debug, warn};

const PRUNABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(4_096);
const IMMUTABLE_ITEMS_PER_SECTION: NonZero<u64> = NZU64!(262_144);
const FREEZER_INITIAL_SIZE: u32 = 65_536; // todo(dalton): Check this default
const FREEZER_TABLE_RESIZE_FREQUENCY: u8 = 4;
const FREEZER_TABLE_RESIZE_CHUNK_SIZE: u32 = 2u32.pow(16); // 3MB
const FREEZER_JOURNAL_TARGET_SIZE: u64 = 1024 * 1024 * 1024; // 1GB

const REPLAY_BUFFER: usize = 8 * 1024 * 1024;
const WRITE_BUFFER: usize = 1024 * 1024;

pub struct Actor<R: Storage + Metrics + Clock + Spawner + governor::clock::Clock> {
    context: R,
    mailbox: mpsc::Receiver<Message>,
    // Blocks verified stored by view<>digest
    verified: PrunableArchive<TwoCap, R, Digest, Block>,
    // Blocks notarized stored by view<>digest
    notarized: PrunableArchive<TwoCap, R, Digest, Notarized>,

    // Finalizations stored by height
    finalized: ImmutableArchive<R, Digest, Finalization<Signature, Digest>>,
    // Blocks finalized stored by height
    //
    // We store this separately because we may not have the finalization for a block
    blocks: ImmutableArchive<R, Digest, Block>,
    orchestrator_mailbox: mpsc::Receiver<Orchestration>,
    public_key: PublicKey,
    participants: Vec<PublicKey>,
    mailbox_size: usize,
    backfill_quota: Quota,
    activity_timeout: u64,
    namespace: String,
}

impl<R: Storage + Metrics + Clock + Spawner + governor::clock::Clock + Rng> Actor<R> {
    pub async fn new(context: R, config: crate::Config) -> (Self, Mailbox, Orchestrator) {
        let (tx, rx) = mpsc::channel(config.mailbox_size);

        // todo: mess with these defaults
        let verified_archive = PrunableArchive::init(
            context.with_label("verified_archive"),
            archive::prunable::Config {
                translator: TwoCap,
                partition: format!("{}-verified-archive", config.partition_prefix),
                compression: None,
                codec_config: (),
                items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                write_buffer: NonZero::new(WRITE_BUFFER).expect("not zero"),
                replay_buffer: NonZero::new(REPLAY_BUFFER).expect("not zero"),
                buffer_pool: config.buffer_pool.clone(),
            },
        )
        .await
        .expect("failed to init verified archive");

        let notarized_archive = PrunableArchive::init(
            context.with_label("notarized_archive"),
            archive::prunable::Config {
                translator: TwoCap,
                partition: format!("{}-notarized-archive", config.partition_prefix),
                compression: None,
                codec_config: (),
                items_per_section: PRUNABLE_ITEMS_PER_SECTION,
                write_buffer: NonZero::new(WRITE_BUFFER).expect("not zero"),
                replay_buffer: NonZero::new(REPLAY_BUFFER).expect("not zero"),
                buffer_pool: config.buffer_pool.clone(),
            },
        )
        .await
        .expect("failed to init verified archive");

        let finalized_archive = ImmutableArchive::init(
            context.with_label("finalized_archive"),
            archive::immutable::Config {
                metadata_partition: format!("{}-finalized-metadata", config.partition_prefix),
                freezer_table_partition: format!("{}-finalized-table", config.partition_prefix),
                freezer_table_initial_size: FREEZER_INITIAL_SIZE,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_journal_partition: format!("{}-finalized-journal", config.partition_prefix),
                freezer_journal_target_size: FREEZER_JOURNAL_TARGET_SIZE,
                freezer_journal_compression: Some(3),
                freezer_journal_buffer_pool: config.buffer_pool.clone(),
                ordinal_partition: format!("{}-finalized-ordinal", config.partition_prefix),
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                write_buffer: NonZero::new(WRITE_BUFFER).expect("not zero"),
                replay_buffer: NonZero::new(REPLAY_BUFFER).expect("not zero"),
                codec_config: usize::MAX,
            },
        )
        .await
        .expect("failed to init verified archive");

        let block_archive = ImmutableArchive::init(
            context.with_label("block_archive"),
            archive::immutable::Config {
                metadata_partition: format!("{}-block-metadata", config.partition_prefix),
                freezer_table_partition: format!("{}-block-table", config.partition_prefix),
                freezer_table_initial_size: FREEZER_INITIAL_SIZE,
                freezer_table_resize_frequency: FREEZER_TABLE_RESIZE_FREQUENCY,
                freezer_table_resize_chunk_size: FREEZER_TABLE_RESIZE_CHUNK_SIZE,
                freezer_journal_partition: format!("{}-block-journal", config.partition_prefix),
                freezer_journal_target_size: FREEZER_JOURNAL_TARGET_SIZE,
                freezer_journal_compression: Some(3),
                freezer_journal_buffer_pool: config.buffer_pool,
                ordinal_partition: format!("{}-block-ordinal", config.partition_prefix),
                items_per_section: IMMUTABLE_ITEMS_PER_SECTION,
                write_buffer: NonZero::new(WRITE_BUFFER).expect("not zero"),
                replay_buffer: NonZero::new(REPLAY_BUFFER).expect("not zero"),
                codec_config: (),
            },
        )
        .await
        .expect("failed to init verified archive");

        let (orchestrator_sender, orchestrator_mailbox) = mpsc::channel(2); // buffer to send processed while moving forward

        (
            Self {
                context,
                mailbox: rx,
                verified: verified_archive,
                notarized: notarized_archive,
                finalized: finalized_archive,
                blocks: block_archive,
                public_key: config.public_key,
                participants: config.participants,
                mailbox_size: config.mailbox_size,
                backfill_quota: config.backfill_quota,
                activity_timeout: config.activity_timeout,
                namespace: config.namespace,
                orchestrator_mailbox,
            },
            Mailbox::new(tx),
            Orchestrator::new(orchestrator_sender),
        )
    }

    pub fn start(
        mut self,
        buffer: buffered::Mailbox<PublicKey, Block>,
        backfill: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        tx_finalizer: mpsc::Sender<()>,
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(buffer, backfill, tx_finalizer))
    }

    pub async fn run(
        mut self,
        mut buffer: buffered::Mailbox<PublicKey, Block>,
        backfill: (
            impl Sender<PublicKey = PublicKey>,
            impl Receiver<PublicKey = PublicKey>,
        ),
        mut tx_finalizer: mpsc::Sender<()>,
    ) {
        let coordinator = Coordinator::new(self.participants.clone());
        let (handler_sender, mut handler_receiver) = mpsc::channel(self.mailbox_size);
        let handler = Handler::new(handler_sender);

        let (resolver_engine, mut resolver) = p2p::Engine::new(
            self.context.with_label("resolver"),
            p2p::Config {
                coordinator,
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.mailbox_size,
                requester_config: requester::Config {
                    public_key: self.public_key.clone(),
                    rate_limit: self.backfill_quota,
                    initial: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                },
                fetch_retry_timeout: Duration::from_millis(100), // prevent busy loop
                priority_requests: false,
                priority_responses: false,
            },
        );

        resolver_engine.start(backfill);

        let mut latest_view = 0;
        let mut requested_blocks = BTreeSet::new();
        let mut last_view_processed: u64 = 0;
        let mut outstanding_notarize = BTreeSet::new();
        loop {
            // Cancel useless requests
            let mut to_cancel = Vec::new();
            outstanding_notarize.retain(|view| {
                if *view < latest_view {
                    to_cancel.push(MultiIndex::new(Value::Notarized(*view)));
                    false
                } else {
                    true
                }
            });
            for view in to_cancel {
                resolver.cancel(view).await;
            }

            select! {
                mailbox_message = self.mailbox.next() => {
                    let message = mailbox_message.expect("Mailbox closed");
                    match message {
                    Message::Get {
                        view,
                        payload,
                        response,
                    } => {
                        #[cfg(feature = "prom")]
                        let get_start = std::time::Instant::now();

                        #[cfg(feature = "prom")]
                        let buffer_lookup_start = std::time::Instant::now();

                        // Check if in buffer
                        if let Some(buffered) = buffer
                            .get(None, payload, Some(payload))
                            .await
                            .into_iter()
                            .next()
                        {
                            debug!(height = buffered.height(), "found block in buffer");
                            let _ = response.send(buffered);

                            #[cfg(feature = "prom")]
                            {
                                let buffer_lookup_duration = buffer_lookup_start.elapsed().as_micros() as f64;
                                histogram!("syncer_get_buffer_lookup_micros").record(buffer_lookup_duration);
                                histogram!("syncer_get_total_micros").record(get_start.elapsed().as_micros() as f64);
                                histogram!("syncer_get_location").record(0.0); // 0 = buffer
                            }

                            continue;
                        }

                        #[cfg(feature = "prom")]
                        {
                            let buffer_lookup_duration = buffer_lookup_start.elapsed().as_micros() as f64;
                            histogram!("syncer_get_buffer_lookup_micros").record(buffer_lookup_duration);
                        }

                        #[cfg(feature = "prom")]
                        let verified_lookup_start = std::time::Instant::now();

                        // check verified blocks
                        if let Some(block) = self
                            .verified
                            .get(Identifier::Key(&payload))
                            .await
                            .expect("Failed to read verified block store")
                        {
                            debug!(height = block.height(), "found block in verified");
                            let _ = response.send(block);

                            #[cfg(feature = "prom")]
                            {
                                let verified_lookup_duration = verified_lookup_start.elapsed().as_micros() as f64;
                                histogram!("syncer_get_verified_lookup_micros").record(verified_lookup_duration);
                                histogram!("syncer_get_total_micros").record(get_start.elapsed().as_micros() as f64);
                                histogram!("syncer_get_location").record(1.0); // 1 = verified
                            }

                            continue;
                        }

                        #[cfg(feature = "prom")]
                        {
                            let verified_lookup_duration = verified_lookup_start.elapsed().as_micros() as f64;
                            histogram!("syncer_get_verified_lookup_micros").record(verified_lookup_duration);
                        }

                        #[cfg(feature = "prom")]
                        let notarized_lookup_start = std::time::Instant::now();

                        // check notarized blocks
                        if let Some(notarization) = self.notarized.get(Identifier::Key(&payload)).await.expect("Failed to get notarized block"){
                            let block = notarization.block;
                            debug!(height = block.height(), "found block in notarized");
                            let _ = response.send(block);

                            #[cfg(feature = "prom")]
                            {
                                let notarized_lookup_duration = notarized_lookup_start.elapsed().as_micros() as f64;
                                histogram!("syncer_get_notarized_lookup_micros").record(notarized_lookup_duration);
                                histogram!("syncer_get_total_micros").record(get_start.elapsed().as_micros() as f64);
                                histogram!("syncer_get_location").record(2.0); // 2 = notarized
                            }

                            continue;

                        }

                        #[cfg(feature = "prom")]
                        {
                            let notarized_lookup_duration = notarized_lookup_start.elapsed().as_micros() as f64;
                            histogram!("syncer_get_notarized_lookup_micros").record(notarized_lookup_duration);
                        }

                        #[cfg(feature = "prom")]
                        let finalized_lookup_start = std::time::Instant::now();

                        // check finalized blocks
                        if let Some(block) = self.blocks.get(Identifier::Key(&payload)).await.expect("Failed to get finalized block") {
                            debug!(height = block.height(), "found block in finalized");
                            let _ = response.send(block);

                            #[cfg(feature = "prom")]
                            {
                                let finalized_lookup_duration = finalized_lookup_start.elapsed().as_micros() as f64;
                                histogram!("syncer_get_finalized_lookup_micros").record(finalized_lookup_duration);
                                histogram!("syncer_get_total_micros").record(get_start.elapsed().as_micros() as f64);
                                histogram!("syncer_get_location").record(3.0); // 3 = finalized
                            }

                            continue;
                        }

                        #[cfg(feature = "prom")]
                        {
                            let finalized_lookup_duration = finalized_lookup_start.elapsed().as_micros() as f64;
                            histogram!("syncer_get_finalized_lookup_micros").record(finalized_lookup_duration);
                            histogram!("syncer_get_location").record(4.0); // 4 = not found
                        }

                        // Fetch from network if notarized (view is non-nil)
                        if let Some(view) = view {
                            debug!(view, ?payload, "required block missing");

                            #[cfg(feature = "prom")]
                            let resolver_fetch_start = std::time::Instant::now();

                            resolver.fetch(MultiIndex::new(Value::Notarized(view))).await;

                            #[cfg(feature = "prom")]
                            {
                                let resolver_fetch_duration = resolver_fetch_start.elapsed().as_micros() as f64;
                                histogram!("syncer_resolver_fetch_micros").record(resolver_fetch_duration);
                            }
                        }

                        buffer
                            .subscribe_prepared(None, payload, Some(payload), response)
                            .await;
                    }
                    Message::Broadcast { payload } => {
                        let ack = buffer.broadcast(Recipients::All, payload).await;

                        drop(ack);
                    }
                    Message::StoreVerified { view, payload } => {
                        match self.verified.put_sync(view, payload.digest(), payload).await {
                            Ok(_) => {
                                debug!(view, "verified block stored");
                            }
                            Err(archive::Error::AlreadyPrunedTo(_)) => {
                                debug!(view, "verified block already pruned");
                            }
                            Err(e) => {
                                panic!("Failed to insert verified block: {e}");
                            }
                        }
                    }
                    Message::Finalize {finalization} => {
                        let view = finalization.view();
                        // Check if in buffer
                        let proposal = &finalization.proposal;
                        let mut block = buffer.get(None, proposal.payload, Some(proposal.payload)).await.into_iter().next();

                        // Check if in verified
                        if block.is_none() {
                            block = self.verified.get(Identifier::Key(&proposal.payload)).await.expect("Failed to get verified block");
                        }

                        // Check if in notarized
                        if block.is_none() {
                            block = self.notarized.get(Identifier::Key(&proposal.payload)).await.expect("Failed to get notarized block").map(|notarized| notarized.block);
                        }

                        if let Some(block) = block {
                            let digest = proposal.payload;
                            let height = block.height();

                            // persist the finalization
                            self.finalized.put_sync(height, digest, finalization).await.expect("Failed to insert into finalization store");
                            self.blocks.put_sync(height, digest,block).await.expect("failed to insert into block store");

                            // prune blocks
                            let min_view = last_view_processed.saturating_sub(self.activity_timeout);
                            self.verified.prune(min_view).await.expect("Failed to prune verified blocks");
                            self.notarized.prune(min_view).await.expect("Failed to prune notarized blocks");

                            // notify finalizer
                            let _ = tx_finalizer.try_send(());

                            // update latest
                            latest_view = view;

                            continue;
                        }

                        // Fetch from network
                        warn!(view, digest = ?proposal.payload, "finalized block missing");
                        resolver.fetch(MultiIndex::new(Value::Digest(proposal.payload))).await;
                    }
                    Message::Notarize{notarization} => {
                        let view = notarization.view();
                        // Check if in buffer
                        let proposal = &notarization.proposal;
                        let mut block =  buffer.get(None, proposal.payload, Some(proposal.payload)).await.into_iter().next();

                        // Check if in verified blocks
                        if block.is_none() {
                            block = self.verified.get(Identifier::Key(&proposal.payload)).await.expect("Failed to get verified block");
                        }

                        if let Some(block) = block {
                            let height = block.height();
                            let digest = proposal.payload;
                            let notarization = Notarized::new(notarization, block);

                            // Persist the notarization
                            match self.notarized.put_sync(view,digest,notarization).await {
                                Ok(_) => {
                                    debug!(view,height, "notarized block stored")
                                }
                                Err(archive::Error::AlreadyPrunedTo(_)) => {
                                    debug!(view, "notarized already pruned");
                                }
                                Err(e) => {
                                    panic!("Failed to insert notarized block: {e}");
                                }
                            };
                            continue;
                        }

                        debug!(view, "notarized block missing");
                        outstanding_notarize.insert(view);

                        #[cfg(feature = "prom")]
                        let resolver_fetch_start = std::time::Instant::now();

                        resolver.fetch(MultiIndex::new(Value::Notarized(view))).await;

                        #[cfg(feature = "prom")]
                        {
                            let resolver_fetch_duration = resolver_fetch_start.elapsed().as_micros() as f64;
                            histogram!("syncer_resolver_fetch_micros").record(resolver_fetch_duration);
                        }

                    }
                }
                },
                orchestrator_message = self.orchestrator_mailbox.next() => {
                    let orchestrator_message = orchestrator_message.expect("Orchestrator closed");
                    match orchestrator_message {
                        Orchestration::Get { next, result } => {
                            // Check if in blocks
                            let block = self.blocks.get(Identifier::Index(next)).await.expect("Failed to get finalized block");
                            result.send(block).expect("Failed to send block");
                        },
                        Orchestration::GetWithFinalization { next, result } => {
                            let block = self.blocks.get(Identifier::Index(next)).await.expect("Failed to get finalized block");
                            let finalized = self.finalized.get(Identifier::Index(next)).await.expect("Failed to get finalized block");
                            result.send((block, finalized)).expect("Failed to send block with finalized");
                        },
                        Orchestration::Processed { next, digest } => {
                            // Cancel any outstanding requests (by height and by digest)
                            resolver.cancel(MultiIndex::new(Value::Finalized(next))).await;
                            resolver.cancel(MultiIndex::new(Value::Digest(digest))).await;

                            // If finalization exists, mark as last_view_processed
                            let finalization = self.finalized.get(Identifier::Index(next)).await.expect("Failed to get finalized block");
                            if let Some(finalization) = finalization {
                                last_view_processed = finalization.view();
                            }

                            // Drain requested blocks less than next
                            requested_blocks.retain(|height| *height > next);
                        },
                        Orchestration::Repair { next, result } => {
                            // While this should never happen, if the height is less than the sync
                            // height, then we don't need to repair.
                            // todo(dalton) make sure this is an okay check to remove now that we are not aware of sync_height in syncer
                            // if next < sync_height {
                            //     continue;
                            // }

                            // Find next gap
                            let (_, start_next) = self.blocks.next_gap(next);
                            let start_next = if let Some(start_next) = start_next {
                                start_next
                            } else {
                                // No gap found by next_gap, but block might still be missing (empty db case)
                                next
                            };

                            // If we are at some height greater than genesis and start_next > next,
                            // attempt to repair the parent of the gapped block
                            if next > 0 && start_next > next {
                                // Get gapped block (the first block after the gap)
                                let gapped_block = self.blocks.get(Identifier::Index(start_next)).await.expect("Failed to get finalized block").expect("Gapped block missing");

                                // Attempt to repair one block from other sources
                                let target_block = gapped_block.parent();
                                let verified = self.verified.get(Identifier::Key(&target_block)).await.expect("Failed to get verified block");
                                if let Some(verified) = verified {
                                    let height = verified.height();
                                    self.blocks.put_sync(height, target_block, verified).await.expect("Failed to insert finalized block");
                                    debug!(height, "repaired block from verified");
                                    result.send(true).expect("Failed to send repair result");
                                    continue;
                                }
                                let notarization = self.notarized.get(Identifier::Key(&target_block)).await.expect("Failed to get notarized block");
                                if let Some(notarization) = notarization {
                                    let height = notarization.block.height();
                                    self.blocks.put_sync(height, target_block, notarization.block).await.expect("Failed to insert finalized block");
                                    debug!(height, "repaired block from notarizations");
                                    result.send(true).expect("Failed to send repair result");
                                    continue;
                                }

                                // Request the parent block digest
                                resolver.fetch(MultiIndex::new(Value::Digest(target_block))).await;
                            }

                            // Enqueue next items (by index)
                            let range_end = if start_next == next {
                                next + 1
                            } else {
                                std::cmp::min(start_next, next + 20)
                            };
                            let range = next..range_end;
                            for height in range {
                                // Check if we've already requested
                                if requested_blocks.contains(&height) {
                                    continue;
                                }

                                // Request the block
                                let key = MultiIndex::new(Value::Finalized(height));
                                resolver.fetch(key).await;
                                requested_blocks.insert(height);
                            }
                            result.send(false).expect("Failed to send repair result");
                        },
                    }
                },
                // Handle resolver messages last
                handler_message = handler_receiver.next() => {
                    let message = handler_message.expect("Handler closed");
                    match message {
                        crate::handler::Message::Deliver { key, value, response } => {
                            match key.to_value() {
                                Value::Notarized(view) => {
                                    // Parse notarization
                                    let Ok(notarization) = Notarized::decode(value.as_ref()) else {
                                        let _ = response.send(false);
                                        continue;
                                    };

                                    if !notarization.proof.verify(self.namespace.as_bytes(), &self.participants) {
                                        let _ = response.send(false);
                                        continue;
                                    }

                                    // Ensure the received payload is for the correct view
                                    if notarization.proof.view() != view {
                                        let _ = response.send(false);
                                        continue;
                                    }

                                    // Persist the notarization
                                    let _ = response.send(true);
                                    match self.notarized
                                        .put_sync(view, notarization.block.digest(), notarization)
                                        .await {
                                        Ok(_) => {
                                            debug!(view, "notarized stored");
                                        },
                                        Err(archive::Error::AlreadyPrunedTo(_)) => {
                                            debug!(view, "notarized already pruned");

                                        }
                                        Err(e) => {
                                            panic!("Failed to insert notarized block: {e}");
                                        }
                                    };
                                }
                                Value::Finalized(height) => {
                                    // Parse finalization
                                    let Ok(finalization) = Finalized::decode(value.as_ref()) else {
                                        let _ = response.send(false);
                                        continue;
                                    };
                                    if !finalization.proof.verify(self.namespace.as_bytes(), &self.participants) {
                                        let _ = response.send(false);
                                        continue;
                                    }

                                    // Ensure the received payload is for the correct height
                                    if finalization.block.height() != height {
                                        let _ = response.send(false);
                                        continue;
                                    }

                                    // Indicate the finalization was valid
                                    debug!(height, "received finalization");
                                    let _ = response.send(true);

                                    // Persist the finalization
                                    self.finalized
                                        .put_sync(height, finalization.block.digest(), finalization.proof )
                                        .await
                                        .expect("Failed to insert finalization");

                                    // Persist the block
                                    self.blocks
                                        .put_sync(height, finalization.block.digest(), finalization.block)
                                        .await
                                        .expect("Failed to insert finalized block");

                                    let _ = tx_finalizer.try_send(());
                                },
                                Value::Digest(digest) => {
                                    // Parse block
                                    let Ok(block) = Block::decode(value.as_ref()) else {
                                        let _ = response.send(false);
                                        continue;
                                    };

                                    // Ensure the received payload is for the correct digest
                                    if block.digest() != digest {
                                        let _ = response.send(false);
                                        continue;
                                    }

                                    // Persist the block
                                    debug!(?digest, height = block.height(), "received block");
                                    let _ = response.send(true);
                                    self.blocks
                                        .put_sync(block.height(), digest, block)
                                        .await
                                        .expect("Failed to insert finalized block");

                                    let _ = tx_finalizer.try_send(());
                                },
                            }
                        }
                        crate::handler::Message::Produce { key, response } => {
                            match key.to_value() {
                                Value::Notarized(view) => {
                                    if let Some(notarized) = self.notarized.get(Identifier::Index(view)).await.expect("Failed to get notarized block") {
                                        let _ = response.send(notarized.encode().into());
                                    } else {
                                        debug!("{view} notarization missing on request");
                                    }
                                }
                                Value::Finalized(height) => {
                                    // get finalization
                                    let Some(finalization) = self.finalized.get(Identifier::Index(height)).await.expect("Failed to get finalization")else {
                                        debug!(height, "Finalization missing on request");
                                        continue;
                                    };

                                    // get block
                                    let Some(block)= self.blocks.get(Identifier::Index(height)).await.expect("Failed to get finalized block") else {
                                        debug!(height, "finalized block missing on request");
                                        continue;
                                    };

                                    // send finalization
                                    let payload = Finalized::new(finalization, block);
                                    let _ = response.send(payload.encode().into());
                                }
                                Value::Digest(digest) => {
                                    // try buffer
                                    if let Some(block) = buffer.get(None, digest, Some(digest)).await.into_iter().next() {
                                        let bytes = block.encode();
                                        let _ = response.send(bytes.into());
                                        continue;
                                    }

                                    // try verified blocks
                                    if let Some(block) = self.verified.get(Identifier::Key(&digest)).await.expect("Failed to get verified block") {
                                        let _ = response.send(block.encode().into());
                                        continue;
                                    }

                                    // try notarized blocks
                                    if let Some(notarized) = self.notarized.get(Identifier::Key(&digest)).await.expect("Failed to get notarized block") {
                                        let _ = response.send(notarized.block.encode().into());
                                        continue;
                                    }

                                    // try blocks
                                    if let Some(block) = self.blocks.get(Identifier::Key(&digest)).await.expect("Failed to get finalized block") {
                                        let _ = response.send(block.encode().into());
                                        continue;
                                    }

                                    // No record of block
                                    debug!(?digest, "block missing on request");
                                },
                            }
                        },
                    }
                }
            }
        }
    }
}
