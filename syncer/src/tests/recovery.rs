//! Restart/pruning regressions with real section-prunable finalized archives.
use super::*;
use commonware_consensus::{Epochable as _, Heightable as _, Viewable as _};
use commonware_storage::archive::Identifier as ArchiveID;

async fn start_prunable(
    context: deterministic::Context,
    validator: K,
    scheme: S,
    height: u64,
) -> (
    Application<B, S>,
    crate::Mailbox<S, B>,
    RecordingResolver,
    commonware_runtime::Handle<()>,
) {
    let oracle = setup_network(context.child("network"), NZUsize!(1));
    let control = oracle.control(validator.clone());
    let (broadcast, buffer) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: validator,
            mailbox_size: NZUsize!(100),
            deque_size: 10,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
        },
    );
    broadcast.start(control.register(2, TEST_QUOTA).await.unwrap());
    let (certificates, blocks) = paced_finalized_stores(
        &context,
        "recovery",
        Duration::ZERO,
        FinalizedSyncFailure::None,
    )
    .await;
    let (actor, mailbox) = actor::Actor::init(
        context.child("actor"),
        certificates.inner,
        blocks.inner,
        Config {
            scheme_provider: ConstantProvider::new(scheme),
            epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
            mailbox_size: NZUsize!(100),
            namespace: NAMESPACE.to_vec(),
            view_retention_timeout: ViewDelta::new(10),
            max_repair: NZUsize!(10),
            max_pending_acks: NZUsize!(1),
            block_codec_config: (),
            partition_prefix: "recovery".into(),
            prunable_items_per_section: NZU64!(10),
            replay_buffer: NZUsize!(1024),
            key_write_buffer: NZUsize!(1024),
            value_write_buffer: NZUsize!(1024),
            page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            strategy: Sequential,
        },
    )
    .await;
    let (rx, resolver) = RecordingResolver::holding(context.child("resolver"));
    let application = Application::default();
    let handle = actor.start(
        application.clone(),
        buffer,
        (rx, resolver.clone()),
        // Deliberately newer than the archive round: startup must not use this
        // diagnostic view to suppress a successor certificate's missing block.
        SyncStart {
            height,
            epoch: height / BLOCKS_PER_EPOCH.get() + 1,
            view: 1000,
        },
        None,
    );
    assert!(mailbox.get_processed_height().await.is_some());
    (application, mailbox, resolver, handle)
}

fn chain(schemes: &[S], count: u64) -> Vec<(B, Finalization<S, D>)> {
    let mut parent = Sha256::hash(&[b""]);
    (1..=count)
        .map(|height| {
            let block = B::new::<Sha256>(parent, Height::new(height), height);
            parent = block.digest();
            let round = Round::new(block.epoch(), block.view());
            let certificate = make_finalization(
                Proposal::new(round, View::new(height - 1), block.digest()),
                schemes,
                QUORUM,
            );
            (block, certificate)
        })
        .collect()
}

async fn seed(
    context: &deterministic::Context,
    chain: &[(B, Finalization<S, D>)],
    missing: Option<u64>,
) {
    let (certificates, blocks) = paced_finalized_stores(
        context,
        "recovery",
        Duration::ZERO,
        FinalizedSyncFailure::None,
    )
    .await;
    let (mut certificates, mut blocks) = (certificates.inner, blocks.inner);
    for (block, certificate) in chain {
        certificates = Certificates::put(
            certificates,
            block.height(),
            block.digest(),
            certificate.clone(),
        )
        .await
        .unwrap();
        if missing != Some(block.height().get()) {
            blocks = Blocks::put(blocks, block.clone()).await.unwrap();
        }
    }
    Certificates::sync(certificates).await.unwrap();
    Blocks::sync(blocks).await.unwrap();
}

async fn processed(context: &deterministic::Context, mailbox: &crate::Mailbox<S, B>, height: u64) {
    while mailbox.get_processed_height().await != Some(Height::new(height)) {
        context.sleep(Duration::from_millis(1)).await;
    }
}

#[test_traced("WARN")]
fn explicit_prune_preserves_replay_history_after_restart() {
    pruning_restart(false);
}

#[test_traced("WARN")]
fn set_floor_preserves_replay_history_after_restart() {
    pruning_restart(true);
}

fn pruning_restart(set_floor: bool) {
    let ((validator, scheme, history), recovered) = deterministic::Runner::timed(
        Duration::from_secs(60),
    )
    .start_and_recover(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);
        let history = chain(&schemes, 40);
        seed(&context, &history[..35], None).await;
        let (application, mut mailbox, _, handle) = start_prunable(
            context.child("live"),
            participants[0].clone(),
            schemes[0].clone(),
            19,
        )
        .await;
        processed(&context, &mailbox, 35).await;
        assert_eq!(
            application.blocks().keys().copied().collect::<Vec<_>>(),
            (20..=35).collect::<Vec<_>>()
        );
        // Invalid requests must still be ignored BEFORE clamping, rather
        // than deleting an otherwise-safe old section.
        mailbox.prune(Height::new(36));
        assert!(mailbox.get_block(1u64).await.is_some());
        assert!(mailbox.get_finalization(Height::new(1)).await.is_some());
        if set_floor {
            let (anchor, certificate) = &history[39];
            assert!(mailbox.verified(certificate.round(), anchor.clone()).await);
            mailbox.set_floor(certificate.clone());
            processed(&context, &mailbox, 40).await;
            assert_eq!(application.blocks().get(&40), Some(anchor));
        } else {
            mailbox.prune(Height::new(35));
        }
        // Section size is ten: cutoff min(request, H+1)=20 must really
        // delete both old sections, not just preserve successors by accident.
        for height in 1..=19 {
            assert!(
                mailbox.get_block(height).await.is_none(),
                "block {height} not pruned"
            );
            assert!(
                mailbox
                    .get_finalization(Height::new(height))
                    .await
                    .is_none(),
                "certificate {height} not pruned"
            );
        }
        for height in 20..=35 {
            assert_eq!(
                mailbox.get_block(height).await,
                Some(history[height as usize - 1].0.clone())
            );
            assert!(
                mailbox
                    .get_finalization(Height::new(height))
                    .await
                    .is_some()
            );
        }
        handle.abort();
        let _ = handle.await;
        (participants[0].clone(), schemes[0].clone(), history)
    });
    deterministic::Runner::from(recovered).start(|context| async move {
        let (application, mut mailbox, _, _) =
            start_prunable(context.child("restart"), validator, scheme, 19).await;
        processed(&context, &mailbox, 35).await;
        assert_eq!(
            application.blocks(),
            history[19..35]
                .iter()
                .map(|(b, _)| (b.height().get(), b.clone()))
                .collect()
        );
        for height in 1..=19 {
            assert!(mailbox.get_block(height).await.is_none());
            assert!(
                mailbox
                    .get_finalization(Height::new(height))
                    .await
                    .is_none()
            );
        }
        for height in 20..=35 {
            assert!(
                mailbox
                    .get_finalization(Height::new(height))
                    .await
                    .is_some()
            );
        }
    });
}

#[test_traced("WARN")]
fn restart_after_pruning_keeps_certificate_only_successor_fetchable() {
    let ((validator, scheme, successor), recovered) = deterministic::Runner::timed(
        Duration::from_secs(60),
    )
    .start_and_recover(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);
        let history = chain(&schemes, 20);
        seed(&context, &history, Some(20)).await;
        // Reproduce the on-disk result of pruning up to H+1 with H=19.
        // Only the successor certificate remains, without its block.
        let (certificates, blocks) = paced_finalized_stores(
            &context,
            "recovery",
            Duration::ZERO,
            FinalizedSyncFailure::None,
        )
        .await;
        let certificates = Certificates::prune(certificates.inner, Height::new(20))
            .await
            .unwrap();
        let blocks = Blocks::prune(blocks.inner, Height::new(20)).await.unwrap();
        assert!(
            Certificates::get(&certificates, ArchiveID::Index(19))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            Blocks::get(&blocks, ArchiveID::Index(19))
                .await
                .unwrap()
                .is_none()
        );
        (
            participants[0].clone(),
            schemes[0].clone(),
            history[19].clone(),
        )
    });
    deterministic::Runner::from(recovered).start(|context| async move {
        let (application, mut mailbox, resolver, _) =
            start_prunable(context.child("restart"), validator, scheme, 19).await;
        assert!(application.blocks().is_empty());
        let (block, certificate) = successor;
        let _ = mailbox.report(Activity::Finalization(certificate.clone()));
        // The certificate-only successor must not become the processed round:
        // a round-bound acquisition of its missing block must still be permitted.
        wait_until(&context, Duration::from_secs(1), "successor fetch", || {
            resolver
                .active_fetches
                .lock()
                .unwrap()
                .iter()
                .any(|fetch| fetch.key == Key::Block(block.digest()))
        })
        .await;
        let fetch = resolver
            .fetches()
            .into_iter()
            .find(|fetch| fetch.key == Key::Block(block.digest()))
            .unwrap();
        let (response, rx) = oneshot::channel();
        let _ = resolver.enqueue(handler::Message::Deliver {
            delivery: Delivery {
                key: fetch.key,
                subscribers: NonEmptyVec::new((fetch.subscriber, tracing::Span::none())),
            },
            value: block.encode(),
            response,
        });
        assert!(rx.await.unwrap());
        processed(&context, &mailbox, 20).await;
        assert_eq!(application.blocks(), BTreeMap::from([(20, block)]));
    });
}
