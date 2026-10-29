//! Backfill through the opaque resolver from untrusted sources.
use super::*;
use crate::resolver::opaque::{self, Source};
use bytes::Bytes;
use commonware_consensus::{Epochable as _, Heightable as _, Viewable as _};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A finalized chain whose heights' finalizations are signed by `schemes`.
fn chain(schemes: &[S], count: u64, timestamp_offset: u64) -> Vec<(B, Finalization<S, D>)> {
    let mut parent = Sha256::hash(&[b""]);
    (1..=count)
        .map(|height| {
            let block = B::new::<Sha256>(parent, Height::new(height), height + timestamp_offset);
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

/// A source serving one chain the way a node's resolver handler would, and
/// counting requests.
#[derive(Clone)]
struct ChainSource {
    chain: Arc<Vec<(B, Finalization<S, D>)>>,
    calls: Arc<AtomicUsize>,
}

impl ChainSource {
    fn new(chain: Vec<(B, Finalization<S, D>)>) -> Self {
        Self {
            chain: Arc::new(chain),
            calls: Arc::default(),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Source<D> for ChainSource {
    async fn get(&self, key: Key<D>) -> Option<Bytes> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match key {
            Key::Finalized { height } => {
                let (block, finalization) = self.chain.get(height.checked_sub(1)? as usize)?;
                Some((finalization.clone(), block.clone()).encode())
            }
            Key::Block(digest) => self
                .chain
                .iter()
                .find(|(block, _)| block.digest() == digest)
                // A forger answers every block request, with its own block.
                .or(self.chain.last())
                .map(|(block, _)| block.encode()),
            Key::Notarized { .. } => None,
        }
    }
}

#[test_traced("WARN")]
fn opaque_backfill_stores_only_genuine_finalized_blocks() {
    const TIP: u64 = 30;
    deterministic::Runner::timed(Duration::from_secs(120)).start(|mut context| async move {
        let Fixture {
            participants,
            schemes,
            ..
        } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);
        // A different committee signs the forger's fork, so its certificates
        // decode and are well formed but don't verify against ours.
        let Fixture {
            schemes: forger_schemes,
            ..
        } = bls12381_threshold::<V, _>(&mut context, NUM_VALIDATORS);
        let genuine = chain(&schemes, TIP, 0);
        let forged = chain(&forger_schemes, TIP, 1_000);

        let oracle = setup_network(context.child("network"), NZUsize!(1));
        let control = oracle.control(participants[0].clone());
        let (broadcast, buffer) = buffered::Engine::new(
            context.child("broadcast"),
            buffered::Config {
                public_key: participants[0].clone(),
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
            "opaque",
            Duration::ZERO,
            FinalizedSyncFailure::None,
        )
        .await;
        let (actor, mut mailbox) = actor::Actor::init(
            context.child("actor"),
            certificates.inner,
            blocks.inner,
            Config {
                scheme_provider: ConstantProvider::new(schemes[0].clone()),
                epocher: FixedEpocher::new(BLOCKS_PER_EPOCH),
                mailbox_size: NZUsize!(100),
                namespace: NAMESPACE.to_vec(),
                view_retention_timeout: ViewDelta::new(10),
                max_repair: NZUsize!(10),
                max_pending_acks: NZUsize!(1),
                block_codec_config: (),
                partition_prefix: "opaque".into(),
                prunable_items_per_section: NZU64!(10),
                replay_buffer: NZUsize!(1024),
                key_write_buffer: NZUsize!(1024),
                value_write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                strategy: Sequential,
            },
        )
        .await;

        // The forger comes first, so every key is tried against it before the
        // honest source.
        let forger = ChainSource::new(forged);
        let honest = ChainSource::new(genuine.clone());
        let (resolver_rx, handler) = handler::init(context.child("handler"), NZUsize!(100));
        let resolver = opaque::init::<_, _, D, K>(
            context.child("opaque"),
            opaque::Config {
                sources: commonware_utils::non_empty_vec![forger.clone(), honest.clone()],
                timeout: Duration::from_secs(1),
                fetch_retry_timeout: Duration::from_millis(100),
                mailbox_size: NZUsize!(100),
            },
            handler,
        );
        let application = Application::<B, S>::default();
        actor.start(
            application.clone(),
            buffer,
            (resolver_rx, resolver),
            SyncStart {
                height: 0,
                epoch: 0,
                view: 0,
            },
            None,
        );

        // Only the tip is hinted; the syncer backfills the rest.
        mailbox.hint_finalized(Height::new(TIP), NonEmptyVec::new(participants[1].clone()));
        while mailbox.get_processed_height().await != Some(Height::new(TIP)) {
            context.sleep(Duration::from_millis(10)).await;
        }

        assert!(forger.calls() > 0, "the forger was never asked");
        assert_eq!(
            application.blocks(),
            genuine
                .iter()
                .map(|(block, _)| (block.height().get(), block.clone()))
                .collect()
        );
        // Parents fetched by digest are stored without their own certificate,
        // but any certificate stored is the genuine one.
        for (block, finalization) in &genuine {
            if let Some(stored) = mailbox.get_finalization(block.height()).await {
                assert_eq!(&stored, finalization);
            }
        }
        assert_eq!(
            mailbox.get_finalization(Height::new(TIP)).await.as_ref(),
            genuine.last().map(|(_, finalization)| finalization)
        );
    });
}
