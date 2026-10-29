//! The follow driver, which runs in place of the orchestrator.

use super::FollowSource;
use commonware_consensus::types::{Epoch, Epocher, Height};
use commonware_cryptography::{Signer as _, certificate::Provider as _};
use commonware_macros::{select, select_loop};
use commonware_runtime::{Clock, ContextCell, Handle, Metrics, Spawner, spawn_cell};
use commonware_utils::vec::NonEmptyVec;
use futures::{StreamExt as _, channel::mpsc, future::join_all};
use std::time::Duration;
use summit_orchestrator::Message;
use summit_types::scheme::{EpochSchemeProvider, MultisigScheme, SummitSchemeProvider};
use summit_types::{Block, Digest, PrivateKey};
use tracing::{debug, info, warn};

/// How often the driver re-hints the heights it wants.
const HINT_INTERVAL: Duration = Duration::from_millis(200);
/// How often the driver asks sources for their tip, and how long each source
/// has to answer.
const TIP_INTERVAL: Duration = Duration::from_secs(1);
/// How many heights past the processed height may be in flight at once.
///
/// The opaque resolver fetches every hinted height concurrently, so this
/// bounds the load a catching-up follower puts on its sources.
pub const DEFAULT_WINDOW: u64 = 256;

/// Drives a follower's syncer from the finalizer's epoch transitions and the
/// sources' tips.
///
/// Like the orchestrator, it registers each epoch's verifier with the scheme
/// provider when the finalizer enters the epoch. Instead of running Simplex, it
/// hints the syncer to fetch finalized heights, at most [`DEFAULT_WINDOW`]
/// past the processed height and never past the entered epoch's last height:
/// the syncer drops a finalization whose epoch verifier isn't registered, and
/// epoch `e+1`'s verifier only exists once the finalizer has processed epoch
/// `e`'s last block.
pub struct Driver<E, F, ES>
where
    E: Clock + Spawner + Metrics,
    F: FollowSource,
    ES: Epocher,
{
    context: ContextCell<E>,
    transitions: mpsc::UnboundedReceiver<Message>,
    scheme_provider: SummitSchemeProvider,
    syncer: summit_syncer::Mailbox<MultisigScheme, Block>,
    epocher: ES,
    sources: NonEmptyVec<F>,
    window: u64,
}

impl<E, F, ES> Driver<E, F, ES>
where
    E: Clock + Spawner + Metrics,
    F: FollowSource,
    ES: Epocher,
{
    /// Creates a driver and the mailbox the finalizer reports epoch
    /// transitions to.
    pub fn new(
        context: E,
        scheme_provider: SummitSchemeProvider,
        syncer: summit_syncer::Mailbox<MultisigScheme, Block>,
        epocher: ES,
        sources: NonEmptyVec<F>,
        window: u64,
    ) -> (Self, summit_orchestrator::Mailbox) {
        let (sender, transitions) = mpsc::unbounded();
        (
            Self {
                context: ContextCell::new(context),
                transitions,
                scheme_provider,
                syncer,
                epocher,
                sources,
                window,
            },
            summit_orchestrator::Mailbox::new(sender),
        )
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        // `hint_finalized` wants P2P targets, which the opaque resolver ignores.
        let targets = NonEmptyVec::new(PrivateKey::from_seed(0).public_key());
        // Tips are polled in a child task, so a slow or hanging source never
        // holds up hints or epoch transitions. It stops with the driver.
        let (tip_sender, mut tips) = mpsc::unbounded();
        self.context.child("tips").spawn({
            let sources = self.sources.clone();
            move |context| poll_tips(context, sources, tip_sender)
        });
        let mut epoch = None;
        let mut tip = 0;
        select_loop! {
            self.context,
            on_stopped => {
                info!("context shutdown, stopping follow driver");
            },
            transition = self.transitions.next() => {
                let Some(transition) = transition else {
                    info!("mailbox closed, stopping follow driver");
                    break;
                };
                match transition {
                    Message::Enter(transition) => {
                        // TODO(#481): copied from the orchestrator. Goes away
                        // once the orchestrator is generic over the per-epoch
                        // engine and followers run an epoch fetcher in it.
                        let scheme = <SummitSchemeProvider as EpochSchemeProvider<Digest>>::scheme_for_epoch(
                            &self.scheme_provider,
                            &transition,
                        );
                        if self.scheme_provider.register(transition.epoch, scheme) {
                            info!(epoch = transition.epoch.get(), "entered epoch");
                        } else {
                            debug!(epoch = transition.epoch.get(), "entered existing epoch");
                        }
                        epoch = epoch.max(Some(transition.epoch));
                    }
                    Message::Exit(exited) => {
                        if self.scheme_provider.unregister(&exited) {
                            info!(epoch = exited.get(), "exited epoch");
                        }
                    }
                }
                self.hint(epoch, tip, &targets).await;
            },
            latest = tips.next() => {
                let Some(latest) = latest else {
                    warn!("tip poller stopped, stopping follow driver");
                    break;
                };
                // The poller already sends each round's highest claim. Taking
                // only the latest round's means an inflated claim makes the
                // driver hint ahead only while a source keeps making it.
                tip = latest;
            },
            _ = self.context.sleep(HINT_INTERVAL) => {
                self.hint(epoch, tip, &targets).await;
            },
        }
    }

    /// Hints every height the syncer may fetch now. Re-hinting a height that
    /// is already in flight or stored costs a lookup, not a fetch.
    async fn hint(
        &mut self,
        epoch: Option<Epoch>,
        tip: u64,
        targets: &NonEmptyVec<summit_types::PublicKey>,
    ) {
        let Some(epoch) = epoch else {
            return;
        };
        // Only epochs with a registered verifier can be delivered.
        if self.scheme_provider.scoped(epoch).is_none() {
            return;
        }
        let Some(last) = self.epocher.last(epoch) else {
            return;
        };
        let Some(processed) = self.syncer.get_processed_height().await else {
            return;
        };
        let upper = tip
            .min(last.get())
            .min(processed.get().saturating_add(self.window));
        for height in processed.get() + 1..=upper {
            self.syncer
                .hint_finalized(Height::new(height), targets.clone());
        }
    }
}

/// Sends the highest tip any source claims, every [`TIP_INTERVAL`], until the
/// driver stops listening.
///
/// Sources are untrusted, so each round's highest claim wins: one live source
/// keeps the follower moving, and an inflated claim only makes it request
/// heights early, for as long as the claim is made.
/// Each source gets [`TIP_INTERVAL`] to answer, so one that never does can't
/// hold back the others' tips.
async fn poll_tips<E: Clock, F: FollowSource>(
    context: E,
    sources: NonEmptyVec<F>,
    tips: mpsc::UnboundedSender<u64>,
) {
    loop {
        let claims = join_all(sources.iter().map(|source| {
            let deadline = context.sleep(TIP_INTERVAL);
            async move {
                select! {
                    tip = source.latest_height() => tip,
                    _ = deadline => None,
                }
            }
        }))
        .await;
        match claims.into_iter().flatten().max() {
            Some(latest) => {
                if tips.unbounded_send(latest).is_err() {
                    return;
                }
            }
            None => warn!("no source reported its latest height"),
        }
        context.sleep(TIP_INTERVAL).await;
    }
}
