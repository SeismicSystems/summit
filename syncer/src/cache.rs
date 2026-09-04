use commonware_codec::CodecShared;
use commonware_consensus::simplex::scheme::Scheme;
use commonware_consensus::{
    Block,
    simplex::types::{Finalization, Notarization},
    types::{Epoch, Height, Round, View},
};
use commonware_runtime::{
    BufferPooler, Clock, Handle, Metrics, Spawner, Storage, buffer::paged::CacheRef,
};
use commonware_storage::{
    archive::{self, Archive as _, Identifier, MultiArchive as _, prunable},
    metadata::{self, Metadata},
    translator::TwoCap,
};
use governor::clock::Clock as GClock;
use rand::Rng;
use std::{
    cmp::max,
    collections::BTreeMap,
    num::{NonZero, NonZeroUsize},
    time::Duration,
};
use tracing::{debug, info};

// The key used to store the current epoch in the metadata store.
const CACHED_EPOCHS_KEY: u8 = 0;

/// Configuration parameters for prunable archives.
pub(crate) struct Config {
    pub partition_prefix: String,
    pub prunable_items_per_section: NonZero<u64>,
    pub replay_buffer: NonZeroUsize,
    pub key_write_buffer: NonZeroUsize,
    pub value_write_buffer: NonZeroUsize,
    pub key_page_cache: CacheRef,
}

/// Prunable archives for a single epoch.
struct Cache<
    R: BufferPooler + Rng + Spawner + Metrics + Clock + GClock + Storage,
    B: Block,
    S: Scheme<B::Digest>,
> {
    /// Verified blocks stored by view
    verified_blocks: prunable::Archive<TwoCap, R, B::Digest, B>,
    /// Notarized blocks stored by view
    notarized_blocks: prunable::Archive<TwoCap, R, B::Digest, B>,
    /// Certified blocks indexed by height and keyed by commitment.
    certified_blocks: prunable::Archive<TwoCap, R, B::Digest, B>,
    /// Notarizations stored by view
    notarizations: prunable::Archive<TwoCap, R, B::Digest, Notarization<S, B::Digest>>,
    /// Finalizations stored by view
    finalizations: prunable::Archive<TwoCap, R, B::Digest, Finalization<S, B::Digest>>,
}

impl<
    R: BufferPooler + Rng + Spawner + Metrics + Clock + GClock + Storage,
    B: Block,
    S: Scheme<B::Digest>,
> Cache<R, B, S>
{
    /// Prune view-indexed archives to the given view.
    async fn prune_by_view(&mut self, min_view: View) {
        match futures::try_join!(
            self.verified_blocks.prune(min_view.get()),
            self.notarized_blocks.prune(min_view.get()),
            self.notarizations.prune(min_view.get()),
            self.finalizations.prune(min_view.get()),
        ) {
            Ok(_) => debug!(min_view = %min_view, "pruned archives"),
            Err(e) => panic!("failed to prune archives: {e}"),
        }
    }

    /// Prune height-indexed archives to the given height.
    async fn prune_by_height(&mut self, min_height: Height) {
        self.certified_blocks
            .prune(min_height.get())
            .await
            .expect("failed to prune certified blocks");
    }
}

/// Manages prunable caches and their metadata.
pub(crate) struct Manager<
    R: BufferPooler + Rng + Spawner + Metrics + Clock + GClock + Storage,
    B: Block,
    S: Scheme<B::Digest>,
> {
    /// Context
    context: R,

    /// Configuration for underlying prunable archives
    cfg: Config,

    /// Codec configuration for block type
    block_codec_config: B::Cfg,

    /// Metadata store for recording which epochs may have data. The value is a tuple of the floor
    /// and ceiling, the minimum and maximum epochs (inclusive) that may have data.
    metadata: Metadata<R, u8, (Epoch, Epoch)>,

    /// A map from epoch to its cache
    caches: BTreeMap<Epoch, Cache<R, B, S>>,
}

impl<
    R: BufferPooler + Rng + Spawner + Metrics + Clock + GClock + Storage,
    B: Block,
    S: Scheme<B::Digest>,
> Manager<R, B, S>
{
    /// Initialize the cache manager and its metadata store.
    pub(crate) async fn init(context: R, cfg: Config, block_codec_config: B::Cfg) -> Self {
        // Initialize metadata
        let metadata = Metadata::init(
            context.child("metadata"),
            metadata::Config {
                partition: format!("{}-metadata", cfg.partition_prefix),
                codec_config: ((), ()),
            },
        )
        .await
        .expect("failed to initialize metadata");

        // We don't eagerly initialize any epoch caches here, they will be
        // initialized on demand, otherwise there could be coordination issues
        // around the scheme provider.
        Self {
            context,
            cfg,
            block_codec_config,
            metadata,
            caches: BTreeMap::new(),
        }
    }

    /// Load all persisted epoch caches so that `find_block` can discover
    /// blocks written before the last shutdown.
    pub(crate) async fn load_persisted_epochs(&mut self) {
        let (floor, ceiling) = self.get_metadata();
        for e in floor.get()..=ceiling.get() {
            let epoch = Epoch::new(e);
            if !self.caches.contains_key(&epoch) {
                self.init_epoch(epoch).await;
            }
        }
    }

    /// Retrieve the epoch range that may have data.
    fn get_metadata(&self) -> (Epoch, Epoch) {
        self.metadata
            .get(&CACHED_EPOCHS_KEY)
            .cloned()
            .unwrap_or((Epoch::zero(), Epoch::zero()))
    }

    /// Set the epoch range that may have data.
    async fn set_metadata(&mut self, floor: Epoch, ceiling: Epoch) {
        self.metadata
            .put_sync(CACHED_EPOCHS_KEY, (floor, ceiling))
            .await
            .expect("failed to write metadata");
    }

    /// Get the cache for the given epoch, initializing it if it doesn't exist.
    ///
    /// If the epoch is less than the minimum cached epoch, then it has already been pruned,
    /// and this will return `None`.
    async fn get_or_init_epoch(&mut self, epoch: Epoch) -> Option<&mut Cache<R, B, S>> {
        // If the cache exists, return it
        if self.caches.contains_key(&epoch) {
            return self.caches.get_mut(&epoch);
        }

        // If the epoch is less than the epoch floor, then it has already been pruned
        let (floor, ceiling) = self.get_metadata();
        if epoch < floor {
            return None;
        }

        // Update the metadata (metadata-first is safe; init is idempotent)
        if epoch > ceiling {
            self.set_metadata(floor, epoch).await;
        }

        // Initialize and return the epoch
        self.init_epoch(epoch).await;
        self.caches.get_mut(&epoch) // Should always be Some
    }

    /// Helper to initialize the cache for a given epoch.
    async fn init_epoch(&mut self, epoch: Epoch) {
        let context = self.context.child("epoch").with_attribute("epoch", epoch);
        let (verified_blocks, notarized_blocks, certified_blocks, notarizations, finalizations) = futures::join!(
            Self::init_archive(
                &context,
                &self.cfg,
                epoch,
                "verified",
                self.block_codec_config.clone()
            ),
            Self::init_archive(
                &context,
                &self.cfg,
                epoch,
                "notarized",
                self.block_codec_config.clone()
            ),
            Self::init_archive(
                &context,
                &self.cfg,
                epoch,
                "certified",
                self.block_codec_config.clone()
            ),
            Self::init_archive(
                &context,
                &self.cfg,
                epoch,
                "notarizations",
                S::certificate_codec_config_unbounded(),
            ),
            Self::init_archive(
                &context,
                &self.cfg,
                epoch,
                "finalizations",
                S::certificate_codec_config_unbounded(),
            ),
        );
        let existing = self.caches.insert(
            epoch,
            Cache {
                verified_blocks,
                notarized_blocks,
                certified_blocks,
                notarizations,
                finalizations,
            },
        );
        assert!(existing.is_none(), "cache already exists for epoch {epoch}");
    }

    /// Helper to initialize an archive.
    async fn init_archive<T: CodecShared>(
        ctx: &R,
        cfg: &Config,
        epoch: Epoch,
        name: &'static str,
        codec_config: T::Cfg,
    ) -> prunable::Archive<TwoCap, R, B::Digest, T> {
        let start = ctx.current();
        let archive_cfg = prunable::Config {
            translator: TwoCap,
            key_partition: format!("{}-cache-{epoch}-{name}-key", cfg.partition_prefix),
            key_page_cache: cfg.key_page_cache.clone(),
            value_partition: format!("{}-cache-{epoch}-{name}-value", cfg.partition_prefix),
            items_per_section: cfg.prunable_items_per_section,
            compression: None,
            codec_config,
            replay_buffer: cfg.replay_buffer,
            key_write_buffer: cfg.key_write_buffer,
            value_write_buffer: cfg.value_write_buffer,
        };
        let archive = prunable::Archive::init(ctx.child(name), archive_cfg)
            .await
            .unwrap_or_else(|_| panic!("failed to initialize {name} archive"));
        info!(elapsed = ?ctx.current().duration_since(start).unwrap_or(Duration::ZERO), "restored {name} archive");
        archive
    }

    /// Add a verified block to the prunable archive and start syncing it.
    pub(crate) async fn put_verified(
        &mut self,
        round: Round,
        commitment: B::Digest,
        block: B,
    ) -> Handle<()> {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return Handle::ready(Ok(()));
        };
        let view = round.view().get();
        match cache.verified_blocks.has_at(view, &commitment).await {
            Ok(true) => {
                return Self::handle_start_result(
                    cache.verified_blocks.start_sync().await,
                    round,
                    "verified",
                );
            }
            Ok(false) => {}
            Err(e) => panic!("failed to check verified blocks: {e}"),
        }
        let result = cache
            .verified_blocks
            .put_multi_start_sync(view, commitment, block)
            .await;
        Self::handle_start_result(result, round, "verified")
    }

    /// Add a certified block to the height-indexed archive.
    pub(crate) async fn put_certified(
        &mut self,
        epoch: Epoch,
        height: Height,
        commitment: B::Digest,
        block: B,
    ) {
        let Some(cache) = self.get_or_init_epoch(epoch).await else {
            return;
        };

        // A digest determines its height, so scoping the dedup to this height
        // is exact and avoids fetching values.
        match cache
            .certified_blocks
            .has_at(height.get(), &commitment)
            .await
        {
            Ok(true) => return,
            Ok(false) => {}
            Err(e) => panic!("failed to check certified block: {e}"),
        }

        match cache
            .certified_blocks
            .put_multi_sync(height.get(), commitment, block)
            .await
        {
            Ok(()) => debug!(%height, "cached certified block"),
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(%height, "certified block already pruned");
            }
            Err(e) => panic!("failed to insert certified block: {e}"),
        }
    }

    /// Add a notarized block to the prunable archive and start syncing it.
    pub(crate) async fn put_block(
        &mut self,
        round: Round,
        commitment: B::Digest,
        block: B,
    ) -> Handle<()> {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return Handle::ready(Ok(()));
        };
        let result = cache
            .notarized_blocks
            .put_start_sync(round.view().get(), commitment, block)
            .await;
        Self::handle_start_result(result, round, "notarized")
    }

    /// Add a notarization to the prunable archive and start syncing it.
    pub(crate) async fn put_notarization(
        &mut self,
        round: Round,
        commitment: B::Digest,
        notarization: Notarization<S, B::Digest>,
    ) -> Handle<()> {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return Handle::ready(Ok(()));
        };
        let result = cache
            .notarizations
            .put_start_sync(round.view().get(), commitment, notarization)
            .await;
        Self::handle_start_result(result, round, "notarization")
    }

    /// Add a finalization to the prunable archive.
    pub(crate) async fn put_finalization(
        &mut self,
        round: Round,
        commitment: B::Digest,
        finalization: Finalization<S, B::Digest>,
    ) {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return;
        };
        let result = cache
            .finalizations
            .put_sync(round.view().get(), commitment, finalization)
            .await;
        Self::handle_result(result, round, "finalization");
    }

    /// Helper to debug cache results.
    fn handle_result(result: Result<(), archive::Error>, round: Round, name: &str) {
        match result {
            Ok(_) => {
                debug!(?round, name, "cached");
            }
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(?round, name, "already pruned");
            }
            Err(e) => {
                panic!("failed to insert {name}: {e}");
            }
        }
    }

    fn handle_start_result(
        result: Result<Handle<()>, archive::Error>,
        round: Round,
        name: &str,
    ) -> Handle<()> {
        match result {
            Ok(handle) => {
                debug!(?round, name, "cache sync started");
                handle
            }
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(?round, name, "already pruned");
                Handle::ready(Ok(()))
            }
            Err(e) => panic!("failed to persist {name}: {e}"),
        }
    }

    /// Returns whether the verified archive holds `commitment` at `round`.
    pub(crate) async fn has_verified(&self, round: Round, commitment: &B::Digest) -> bool {
        let Some(cache) = self.caches.get(&round.epoch()) else {
            return false;
        };
        cache
            .verified_blocks
            .has_at(round.view().get(), commitment)
            .await
            .expect("failed to check verified blocks")
    }

    /// Observe all verified-block writes accepted before this call.
    pub(crate) async fn start_sync_verified(&mut self, round: Round) -> Handle<()> {
        let Some(cache) = self.caches.get_mut(&round.epoch()) else {
            return Handle::ready(Ok(()));
        };
        Self::handle_start_result(cache.verified_blocks.start_sync().await, round, "verified")
    }

    /// Observe all notarization writes accepted before this call.
    pub(crate) async fn start_sync_notarizations(&mut self, round: Round) -> Handle<()> {
        let Some(cache) = self.caches.get_mut(&round.epoch()) else {
            return Handle::ready(Ok(()));
        };
        Self::handle_start_result(
            cache.notarizations.start_sync().await,
            round,
            "notarization",
        )
    }

    /// Get a notarization from the prunable archive by round.
    pub(crate) async fn get_notarization(
        &self,
        round: Round,
    ) -> Option<Notarization<S, B::Digest>> {
        let cache = self.caches.get(&round.epoch())?;
        cache
            .notarizations
            .get(Identifier::Index(round.view().get()))
            .await
            .expect("failed to get notarization")
    }

    /// Get a block previously persisted in the verified archive for `round`.
    ///
    /// The archive can hold multiple candidates at one view when a leader
    /// equivocates across a crash. This returns the first stored candidate;
    /// callers must validate its digest and context before reuse.
    pub(crate) async fn get_verified(&self, round: Round) -> Option<B> {
        let cache = self.caches.get(&round.epoch())?;
        cache
            .verified_blocks
            .get(Identifier::Index(round.view().get()))
            .await
            .expect("failed to get verified block")
    }

    /// Get a finalization from the prunable archive by commitment.
    pub(crate) async fn get_finalization_for(
        &self,
        commitment: B::Digest,
    ) -> Option<Finalization<S, B::Digest>> {
        for cache in self.caches.values().rev() {
            match cache.finalizations.get(Identifier::Key(&commitment)).await {
                Ok(Some(finalization)) => return Some(finalization),
                Ok(None) => continue,
                Err(e) => panic!("failed to get cached finalization: {e}"),
            }
        }
        None
    }

    /// Looks for a block (verified, notarized, or certified by height).
    pub(crate) async fn find_block(&self, commitment: B::Digest) -> Option<B> {
        self.find_block_matching(commitment, |_| true).await
    }

    /// Looks for a block (verified, notarized, or certified by height) that matches `predicate`.
    pub(crate) async fn find_block_matching(
        &self,
        commitment: B::Digest,
        mut predicate: impl FnMut(&B) -> bool,
    ) -> Option<B> {
        // Check in reverse order
        for cache in self.caches.values().rev() {
            // Check verified blocks
            if let Some(block) = cache
                .verified_blocks
                .get(Identifier::Key(&commitment))
                .await
                .expect("failed to get verified block")
                && predicate(&block)
            {
                return Some(block);
            }

            // Check notarized blocks
            if let Some(block) = cache
                .notarized_blocks
                .get(Identifier::Key(&commitment))
                .await
                .expect("failed to get notarized block")
                && predicate(&block)
            {
                return Some(block);
            }

            // Check certified blocks
            if let Some(block) = cache
                .certified_blocks
                .get(Identifier::Key(&commitment))
                .await
                .expect("failed to get certified block")
                && predicate(&block)
            {
                return Some(block);
            }
        }
        None
    }

    /// Prune the view-indexed caches below the given round.
    pub(crate) async fn prune_by_view(&mut self, round: Round) {
        // Remove and close prunable archives from older epochs
        let new_floor = round.epoch();
        let old_epochs: Vec<Epoch> = self
            .caches
            .keys()
            .copied()
            .filter(|epoch| *epoch < new_floor)
            .collect();
        for epoch in old_epochs.iter() {
            let Cache::<R, B, S> {
                verified_blocks: vb,
                notarized_blocks: nb,
                certified_blocks: cb,
                notarizations: nv,
                finalizations: fv,
            } = self.caches.remove(epoch).unwrap();
            vb.destroy().await.expect("failed to destroy vb");
            nb.destroy().await.expect("failed to destroy nb");
            cb.destroy().await.expect("failed to destroy cb");
            nv.destroy().await.expect("failed to destroy nv");
            fv.destroy().await.expect("failed to destroy fv");
        }

        // Update metadata if necessary
        let (floor, ceiling) = self.get_metadata();
        if new_floor > floor {
            let new_ceiling = max(ceiling, new_floor);
            self.set_metadata(new_floor, new_ceiling).await;
        }

        // Prune archives for the given epoch
        let min_view = round.view();
        if let Some(prunable) = self.caches.get_mut(&round.epoch()) {
            prunable.prune_by_view(min_view).await;
        }
    }

    /// Prune height-indexed certified blocks below the given height.
    pub(crate) async fn prune_by_height(&mut self, height: Height) {
        for cache in self.caches.values_mut() {
            cache.prune_by_height(height).await;
        }
    }
}
