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
    archive::{Archive as _, Identifier, MultiArchive as _, prunable},
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

const CACHED_EPOCHS_KEY: u8 = 0;

pub(crate) struct Config {
    pub partition_prefix: String,
    pub prunable_items_per_section: NonZero<u64>,
    pub replay_buffer: NonZeroUsize,
    pub key_write_buffer: NonZeroUsize,
    pub value_write_buffer: NonZeroUsize,
    pub key_page_cache: CacheRef,
}

type NotarizationArchive<R, S, D> = prunable::Archive<TwoCap, R, D, Notarization<S, D>>;
type FinalizationArchive<R, S, D> = prunable::Archive<TwoCap, R, D, Finalization<S, D>>;

/// Each handle is absent while a consuming mutation owns it. Failure or
/// cancellation never substitutes an empty archive for a lost handle.
struct Cache<
    R: BufferPooler + Rng + Spawner + Metrics + Clock + GClock + Storage,
    B: Block,
    S: Scheme<B::Digest>,
> {
    verified_blocks: Option<prunable::Archive<TwoCap, R, B::Digest, B>>,
    notarized_blocks: Option<prunable::Archive<TwoCap, R, B::Digest, B>>,
    certified_blocks: Option<prunable::Archive<TwoCap, R, B::Digest, B>>,
    notarizations: Option<NotarizationArchive<R, S, B::Digest>>,
    finalizations: Option<FinalizationArchive<R, S, B::Digest>>,
}

impl<
    R: BufferPooler + Rng + Spawner + Metrics + Clock + GClock + Storage,
    B: Block,
    S: Scheme<B::Digest>,
> Cache<R, B, S>
{
    async fn prune_by_view(&mut self, min_view: View) {
        let verified = self
            .verified_blocks
            .take()
            .expect("verified archive unavailable");
        let notarized = self
            .notarized_blocks
            .take()
            .expect("notarized archive unavailable");
        let notarizations = self
            .notarizations
            .take()
            .expect("notarizations archive unavailable");
        let finalizations = self
            .finalizations
            .take()
            .expect("finalizations archive unavailable");
        let (verified, notarized, notarizations, finalizations) = futures::try_join!(
            verified.prune(min_view.get()),
            notarized.prune(min_view.get()),
            notarizations.prune(min_view.get()),
            finalizations.prune(min_view.get()),
        )
        .expect("failed to prune archives");
        self.verified_blocks = Some(verified);
        self.notarized_blocks = Some(notarized);
        self.notarizations = Some(notarizations);
        self.finalizations = Some(finalizations);
        debug!(%min_view, "pruned archives");
    }

    async fn prune_by_height(&mut self, min_height: Height) {
        let archive = self
            .certified_blocks
            .take()
            .expect("certified archive unavailable");
        self.certified_blocks = Some(
            archive
                .prune(min_height.get())
                .await
                .expect("failed to prune certified blocks"),
        );
    }
}

pub(crate) struct Manager<
    R: BufferPooler + Rng + Spawner + Metrics + Clock + GClock + Storage,
    B: Block,
    S: Scheme<B::Digest>,
> {
    context: R,
    cfg: Config,
    block_codec_config: B::Cfg,
    metadata: Option<Metadata<R, u8, (Epoch, Epoch)>>,
    caches: BTreeMap<Epoch, Cache<R, B, S>>,
}

impl<
    R: BufferPooler + Rng + Spawner + Metrics + Clock + GClock + Storage,
    B: Block,
    S: Scheme<B::Digest>,
> Manager<R, B, S>
{
    #[commonware_macros::boxed]
    pub(crate) async fn init(context: R, cfg: Config, block_codec_config: B::Cfg) -> Self {
        let metadata = Metadata::init(
            context.child("metadata"),
            metadata::Config {
                partition: format!("{}-metadata", cfg.partition_prefix),
                codec_config: ((), ()),
            },
        )
        .await
        .expect("failed to initialize metadata");
        Self {
            context,
            cfg,
            block_codec_config,
            metadata: Some(metadata),
            caches: BTreeMap::new(),
        }
    }

    /// Open persisted caches lazily only after the scheme provider is ready.
    pub(crate) async fn load_persisted_epochs(&mut self) {
        let (floor, ceiling) = self.get_metadata();
        for e in floor.get()..=ceiling.get() {
            let epoch = Epoch::new(e);
            if !self.caches.contains_key(&epoch) {
                self.init_epoch(epoch).await;
            }
        }
    }

    fn get_metadata(&self) -> (Epoch, Epoch) {
        self.metadata
            .as_ref()
            .expect("cache metadata unavailable")
            .get(&CACHED_EPOCHS_KEY)
            .cloned()
            .unwrap_or((Epoch::zero(), Epoch::zero()))
    }

    async fn set_metadata(&mut self, floor: Epoch, ceiling: Epoch) {
        let metadata = self.metadata.take().expect("cache metadata unavailable");
        self.metadata = Some(
            metadata
                .put_sync(CACHED_EPOCHS_KEY, (floor, ceiling))
                .await
                .expect("failed to write metadata"),
        );
    }

    async fn get_or_init_epoch(&mut self, epoch: Epoch) -> Option<&mut Cache<R, B, S>> {
        if self.caches.contains_key(&epoch) {
            return self.caches.get_mut(&epoch);
        }
        let (floor, ceiling) = self.get_metadata();
        if epoch < floor {
            return None;
        }
        // Metadata first: initialization is idempotent after a crash.
        if epoch > ceiling {
            self.set_metadata(floor, epoch).await;
        }
        self.init_epoch(epoch).await;
        self.caches.get_mut(&epoch)
    }

    #[commonware_macros::boxed]
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
                S::certificate_codec_config_unbounded()
            ),
            Self::init_archive(
                &context,
                &self.cfg,
                epoch,
                "finalizations",
                S::certificate_codec_config_unbounded()
            ),
        );
        let existing = self.caches.insert(
            epoch,
            Cache {
                verified_blocks: Some(verified_blocks),
                notarized_blocks: Some(notarized_blocks),
                certified_blocks: Some(certified_blocks),
                notarizations: Some(notarizations),
                finalizations: Some(finalizations),
            },
        );
        assert!(existing.is_none(), "cache already exists for epoch {epoch}");
    }

    async fn init_archive<T: CodecShared>(
        ctx: &R,
        cfg: &Config,
        epoch: Epoch,
        name: &'static str,
        codec_config: T::Cfg,
    ) -> prunable::Archive<TwoCap, R, B::Digest, T> {
        let start = ctx.current();
        let archive = prunable::Archive::init(
            ctx.child(name),
            prunable::Config {
                translator: TwoCap,
                key_partition: format!("{}-cache-{epoch}-{name}-key", cfg.partition_prefix),
                key_page_cache: cfg.key_page_cache.clone(),
                value_partition: format!("{}-cache-{epoch}-{name}-value", cfg.partition_prefix),
                metadata_partition: format!(
                    "{}-cache-{epoch}-{name}-metadata",
                    cfg.partition_prefix
                ),
                items_per_section: cfg.prunable_items_per_section,
                compression: None,
                codec_config,
                replay_buffer: cfg.replay_buffer,
                key_write_buffer: cfg.key_write_buffer,
                value_write_buffer: cfg.value_write_buffer,
            },
        )
        .await
        .unwrap_or_else(|e| panic!("failed to initialize {name} archive: {e}"));
        info!(elapsed = ?ctx.current().duration_since(start).unwrap_or(Duration::ZERO), "restored {name} archive");
        archive
    }

    pub(crate) async fn put_verified(
        &mut self,
        round: Round,
        commitment: B::Digest,
        block: B,
    ) -> Handle<()> {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return Handle::ready(Ok(()));
        };
        let archive = cache
            .verified_blocks
            .take()
            .expect("verified archive unavailable");
        let view = round.view().get();
        let result = if archive
            .has_at(view, &commitment)
            .await
            .expect("failed to check verified blocks")
        {
            archive.start_sync().await
        } else {
            archive.put_multi_start_sync(view, commitment, block).await
        };
        let (archive, handle) = result.expect("failed to persist verified block");
        cache.verified_blocks = Some(archive);
        handle
    }

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
        if cache
            .certified_blocks
            .as_ref()
            .expect("certified archive unavailable")
            .has_at(height.get(), &commitment)
            .await
            .expect("failed to check certified block")
        {
            return;
        }
        let archive = cache
            .certified_blocks
            .take()
            .expect("certified archive unavailable");
        // Below-floor puts are successful no-ops in Commonware 2026.9.0.
        cache.certified_blocks = Some(
            archive
                .put_multi_sync(height.get(), commitment, block)
                .await
                .expect("failed to insert certified block"),
        );
    }

    pub(crate) async fn put_block(
        &mut self,
        round: Round,
        commitment: B::Digest,
        block: B,
    ) -> Handle<()> {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return Handle::ready(Ok(()));
        };
        let archive = cache
            .notarized_blocks
            .take()
            .expect("notarized archive unavailable");
        let (archive, handle) = archive
            .put_start_sync(round.view().get(), commitment, block)
            .await
            .expect("failed to persist notarized block");
        cache.notarized_blocks = Some(archive);
        handle
    }

    pub(crate) async fn put_notarization(
        &mut self,
        round: Round,
        commitment: B::Digest,
        notarization: Notarization<S, B::Digest>,
    ) -> Handle<()> {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return Handle::ready(Ok(()));
        };
        let archive = cache
            .notarizations
            .take()
            .expect("notarizations archive unavailable");
        let (archive, handle) = archive
            .put_start_sync(round.view().get(), commitment, notarization)
            .await
            .expect("failed to persist notarization");
        cache.notarizations = Some(archive);
        handle
    }

    pub(crate) async fn put_finalization(
        &mut self,
        round: Round,
        commitment: B::Digest,
        finalization: Finalization<S, B::Digest>,
    ) {
        let Some(cache) = self.get_or_init_epoch(round.epoch()).await else {
            return;
        };
        let archive = cache
            .finalizations
            .take()
            .expect("finalizations archive unavailable");
        cache.finalizations = Some(
            archive
                .put_sync(round.view().get(), commitment, finalization)
                .await
                .expect("failed to persist finalization"),
        );
    }

    pub(crate) async fn has_verified(&self, round: Round, commitment: &B::Digest) -> bool {
        let Some(cache) = self.caches.get(&round.epoch()) else {
            return false;
        };
        cache
            .verified_blocks
            .as_ref()
            .expect("verified archive unavailable")
            .has_at(round.view().get(), commitment)
            .await
            .expect("failed to check verified blocks")
    }

    pub(crate) async fn start_sync_verified(&mut self, round: Round) -> Handle<()> {
        let Some(cache) = self.caches.get_mut(&round.epoch()) else {
            return Handle::ready(Ok(()));
        };
        let archive = cache
            .verified_blocks
            .take()
            .expect("verified archive unavailable");
        let (archive, handle) = archive
            .start_sync()
            .await
            .expect("failed to sync verified blocks");
        cache.verified_blocks = Some(archive);
        handle
    }

    pub(crate) async fn start_sync_notarizations(&mut self, round: Round) -> Handle<()> {
        let Some(cache) = self.caches.get_mut(&round.epoch()) else {
            return Handle::ready(Ok(()));
        };
        let archive = cache
            .notarizations
            .take()
            .expect("notarizations archive unavailable");
        let (archive, handle) = archive
            .start_sync()
            .await
            .expect("failed to sync notarizations");
        cache.notarizations = Some(archive);
        handle
    }

    pub(crate) async fn get_notarization(
        &self,
        round: Round,
    ) -> Option<Notarization<S, B::Digest>> {
        let cache = self.caches.get(&round.epoch())?;
        cache
            .notarizations
            .as_ref()
            .expect("notarizations archive unavailable")
            .get(Identifier::Index(round.view().get()))
            .await
            .expect("failed to get notarization")
    }

    /// Returns the first candidate at a view; callers must check digest/context
    /// because verified storage retains equivocations across crashes.
    pub(crate) async fn get_verified(&self, round: Round) -> Option<B> {
        let cache = self.caches.get(&round.epoch())?;
        cache
            .verified_blocks
            .as_ref()
            .expect("verified archive unavailable")
            .get(Identifier::Index(round.view().get()))
            .await
            .expect("failed to get verified block")
    }

    pub(crate) async fn get_finalization_for(
        &self,
        commitment: B::Digest,
    ) -> Option<Finalization<S, B::Digest>> {
        for cache in self.caches.values().rev() {
            if let Some(finalization) = cache
                .finalizations
                .as_ref()
                .expect("finalizations archive unavailable")
                .get(Identifier::Key(&commitment))
                .await
                .expect("failed to get cached finalization")
            {
                return Some(finalization);
            }
        }
        None
    }

    pub(crate) async fn find_block(&self, commitment: B::Digest) -> Option<B> {
        self.find_block_matching(commitment, |_| true).await
    }

    pub(crate) async fn find_block_matching(
        &self,
        commitment: B::Digest,
        mut predicate: impl FnMut(&B) -> bool,
    ) -> Option<B> {
        for cache in self.caches.values().rev() {
            for archive in [
                &cache.verified_blocks,
                &cache.notarized_blocks,
                &cache.certified_blocks,
            ] {
                if let Some(block) = archive
                    .as_ref()
                    .expect("block cache unavailable")
                    .get(Identifier::Key(&commitment))
                    .await
                    .expect("failed to get cached block")
                    && predicate(&block)
                {
                    return Some(block);
                }
            }
        }
        None
    }

    pub(crate) async fn prune_by_view(&mut self, round: Round) {
        let new_floor = round.epoch();
        let old_epochs: Vec<_> = self
            .caches
            .keys()
            .copied()
            .filter(|epoch| *epoch < new_floor)
            .collect();
        for epoch in old_epochs {
            let cache = self.caches.remove(&epoch).unwrap();
            cache
                .verified_blocks
                .expect("verified archive unavailable")
                .destroy()
                .await
                .expect("failed to destroy verified archive");
            cache
                .notarized_blocks
                .expect("notarized archive unavailable")
                .destroy()
                .await
                .expect("failed to destroy notarized archive");
            cache
                .certified_blocks
                .expect("certified archive unavailable")
                .destroy()
                .await
                .expect("failed to destroy certified archive");
            cache
                .notarizations
                .expect("notarizations archive unavailable")
                .destroy()
                .await
                .expect("failed to destroy notarizations archive");
            cache
                .finalizations
                .expect("finalizations archive unavailable")
                .destroy()
                .await
                .expect("failed to destroy finalizations archive");
        }
        let (floor, ceiling) = self.get_metadata();
        if new_floor > floor {
            self.set_metadata(new_floor, max(ceiling, new_floor)).await;
        }
        if let Some(cache) = self.caches.get_mut(&round.epoch()) {
            cache.prune_by_view(round.view()).await;
        }
    }

    pub(crate) async fn prune_by_height(&mut self, height: Height) {
        for cache in self.caches.values_mut() {
            cache.prune_by_height(height).await;
        }
    }
}
