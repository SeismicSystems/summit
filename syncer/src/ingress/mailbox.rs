use commonware_actor::{
    Feedback,
    mailbox::{Overflow, Policy, Sender},
};
use commonware_consensus::{
    Block, Reporter,
    simplex::scheme::Scheme,
    simplex::types::{Activity, Finalization, Notarization},
    types::{Height, Round},
};
use commonware_cryptography::Digest;
use commonware_p2p::Recipients;
use commonware_storage::archive;
use commonware_utils::{channel::oneshot, vec::NonEmptyVec};
use futures::{
    FutureExt,
    future::BoxFuture,
    stream::{FuturesOrdered, Stream},
};
use pin_project::pin_project;
use std::{
    collections::{BTreeMap, VecDeque, btree_map::Entry},
    pin::Pin,
    task::{Context, Poll},
};

/// An identifier for a block request.
pub enum Identifier<D: Digest> {
    /// The height of the block to retrieve.
    Height(Height),
    /// The commitment of the block to retrieve.
    Digest(D),
    /// The highest finalized block. It may be the case that marshal does not have some of the
    /// blocks below this height.
    Latest,
}

// Allows using Height directly for convenience.
impl<D: Digest> From<Height> for Identifier<D> {
    fn from(src: Height) -> Self {
        Self::Height(src)
    }
}

// Allows using u64 directly for convenience (converted to Height).
impl<D: Digest> From<u64> for Identifier<D> {
    fn from(src: u64) -> Self {
        Self::Height(Height::new(src))
    }
}

// Allows using &Digest directly for convenience.
impl<D: Digest> From<&D> for Identifier<D> {
    fn from(src: &D) -> Self {
        Self::Digest(*src)
    }
}

// Allows using archive identifiers directly for convenience.
impl<D: Digest> From<archive::Identifier<'_, D>> for Identifier<D> {
    fn from(src: archive::Identifier<'_, D>) -> Self {
        match src {
            archive::Identifier::Index(index) => Self::Height(Height::new(index)),
            archive::Identifier::Key(key) => Self::Digest(*key),
        }
    }
}

/// Messages sent to the marshal [Actor](crate::actor::Actor).
///
/// These messages are sent from the consensus engine and other parts of the
/// system to drive the state of the marshal.
pub(crate) enum Message<S: Scheme<B::Digest>, B: Block> {
    // -------------------- Application Messages --------------------
    /// A request to retrieve the (height, commitment) of a block by its identifier.
    /// The block must be finalized; returns `None` if the block is not finalized.
    GetInfo {
        /// The identifier of the block to get the information of.
        identifier: Identifier<B::Digest>,
        /// A channel to send the retrieved (height, commitment).
        response: oneshot::Sender<Option<(Height, B::Digest)>>,
    },
    /// A request to retrieve a block by its identifier.
    ///
    /// Requesting by [Identifier::Height] or [Identifier::Latest] will only return finalized
    /// blocks, whereas requesting by commitment may return non-finalized or even unverified blocks.
    GetBlock {
        /// The identifier of the block to retrieve.
        identifier: Identifier<B::Digest>,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<Option<B>>,
    },
    /// A request to retrieve a finalization by height.
    GetFinalization {
        /// The height of the finalization to retrieve.
        height: Height,
        /// A channel to send the retrieved finalization.
        response: oneshot::Sender<Option<Finalization<S, B::Digest>>>,
    },
    /// A request to retrieve the latest processed height.
    GetProcessedHeight {
        /// A channel to send the latest processed height.
        response: oneshot::Sender<Option<Height>>,
    },
    /// A hint to fetch a finalization from the network if not available locally.
    ///
    /// This is fire-and-forget: the finalization will be stored in syncer and delivered
    /// via the normal finalization flow when available.
    HintFinalized {
        /// The height of the finalization to fetch.
        height: Height,
        /// Target peers to fetch from. Added to any existing targets for this height.
        targets: NonEmptyVec<S::PublicKey>,
    },
    /// A request to retrieve a block by its commitment.
    Subscribe {
        /// The view in which the block was notarized. This is an optimization
        /// to help locate the block.
        round: Option<Round>,
        /// The commitment of the block to retrieve.
        commitment: B::Digest,
        /// A channel to send the retrieved block.
        response: oneshot::Sender<B>,
    },
    /// A hint to fetch a notarized block by round without adding another local subscriber.
    ///
    /// `commitment` is used as a locality check: if the block is already
    /// available locally, the fetch is skipped.
    HintNotarized {
        /// The notarized round to request.
        round: Round,
        /// The commitment used to short-circuit if the block is already local.
        commitment: B::Digest,
    },
    /// A request to retrieve the verified block previously persisted for `round`.
    GetVerified {
        /// The round to query.
        round: Round,
        /// A channel to send the retrieved block, if any.
        response: oneshot::Sender<Option<B>>,
    },
    /// A request to broadcast a proposed block to all peers.
    Proposed {
        /// The round in which the block was proposed.
        round: Round,
        /// The block to broadcast.
        block: B,
        /// A channel signaled once the block is durably stored.
        ack: Option<oneshot::Sender<()>>,
    },
    /// A request to forward a block to a set of recipients.
    Forward {
        /// The round in which the block was proposed.
        round: Round,
        /// The commitment of the block to forward.
        commitment: B::Digest,
        /// The recipients to forward the block to.
        recipients: Recipients<S::PublicKey>,
    },
    /// A notification that a block has been verified by the application.
    Verified {
        /// The round in which the block was verified.
        round: Round,
        /// The verified block.
        block: B,
        /// A channel signaled once the block is durably stored.
        ack: Option<oneshot::Sender<()>>,
    },
    /// A notification that a block has been certified by the application.
    Certified {
        /// The round in which the block was certified.
        round: Round,
        /// The certified block.
        block: B,
        /// A channel signaled once the block is durably stored.
        ack: Option<oneshot::Sender<()>>,
    },

    // -------------------- Consensus Engine Messages --------------------
    /// A notarization from the consensus engine.
    Notarization {
        /// The notarization.
        notarization: Notarization<S, B::Digest>,
    },
    /// A finalization from the consensus engine.
    Finalization {
        /// The finalization.
        finalization: Finalization<S, B::Digest>,
    },
    /// Attempts to set the sync starting point from a finalized commitment.
    ///
    /// If the verified finalization advances the current floor, the syncer
    /// anchors on its block, prunes below it, then syncs and delivers blocks
    /// starting at the floor height. Stale or superseded floors may be ignored.
    ///
    /// To prune data without changing the sync starting point, use
    /// [Message::Prune] instead.
    SetFloor {
        /// The candidate floor finalization, verified by the actor before use.
        finalization: Finalization<S, B::Digest>,
    },
    /// Prunes finalized blocks and certificates below the given height.
    ///
    /// Unlike [Message::SetFloor], this does not affect the sync starting point.
    /// The height must be at or below the current floor (last processed height),
    /// otherwise the prune request is ignored.
    Prune {
        /// The minimum height to keep (blocks below this are pruned).
        height: Height,
    },
}

impl<S: Scheme<B::Digest>, B: Block> Message<S, B> {
    fn stale(&self, current: Option<Height>) -> bool {
        match self {
            // Height-targeted reads below the floor can never be served
            Self::GetInfo {
                identifier: Identifier::Height(height),
                ..
            }
            | Self::GetBlock {
                identifier: Identifier::Height(height),
                ..
            }
            | Self::GetFinalization { height, .. } => Some(*height) < current,
            // Hints only inform the actor about heights strictly above the floor
            Self::HintFinalized { height, .. } => Some(*height) <= current,
            // Durability acks cannot be dropped: callers depend on them
            Self::Proposed { .. } | Self::Verified { .. } | Self::Certified { .. } => false,
            // Digest and latest lookups are not bound to a specific height
            Self::GetBlock {
                identifier: Identifier::Digest(_) | Identifier::Latest,
                ..
            }
            | Self::GetInfo {
                identifier: Identifier::Digest(_) | Identifier::Latest,
                ..
            }
            | Self::GetProcessedHeight { .. } => false,
            Self::HintNotarized { .. } => false,
            Self::Subscribe { .. }
            | Self::GetVerified { .. }
            | Self::Forward { .. }
            | Self::SetFloor { .. }
            | Self::Prune { .. }
            | Self::Notarization { .. }
            | Self::Finalization { .. } => false,
        }
    }

    pub(crate) fn response_closed(&self) -> bool {
        match self {
            Self::GetInfo { response, .. } => response.is_closed(),
            Self::GetBlock { response, .. } | Self::GetVerified { response, .. } => {
                response.is_closed()
            }
            Self::GetFinalization { response, .. } => response.is_closed(),
            Self::GetProcessedHeight { response } => response.is_closed(),
            Self::Subscribe { response, .. } => response.is_closed(),
            Self::HintNotarized { .. } => false,
            Self::HintFinalized { .. }
            | Self::Forward { .. }
            | Self::Proposed { .. }
            | Self::Verified { .. }
            | Self::Certified { .. }
            | Self::SetFloor { .. }
            | Self::Prune { .. }
            | Self::Notarization { .. }
            | Self::Finalization { .. } => false,
        }
    }
}

/// Overflow state for syncer mailbox messages retained after the mailbox fills.
///
/// Advisory inputs are coalesced instead of queued unboundedly: finalized
/// hints keep one entry per height with a unioned target set, floors collapse
/// to the highest round seen, and prunes collapse to the highest height seen.
/// This keeps callers running control loops (e.g. the orchestrator) from ever
/// parking on a full syncer mailbox.
pub(crate) struct Pending<S: Scheme<B::Digest>, B: Block> {
    floor: Option<Finalization<S, B::Digest>>,
    prune: Option<Height>,
    hints: BTreeMap<Height, NonEmptyVec<S::PublicKey>>,
    messages: VecDeque<PendingMessage<S, B>>,
}

enum PendingMessage<S: Scheme<B::Digest>, B: Block> {
    Message(Message<S, B>),
    HintFinalized(Height),
}

impl<S: Scheme<B::Digest>, B: Block> Default for Pending<S, B> {
    fn default() -> Self {
        Self {
            floor: None,
            prune: None,
            hints: BTreeMap::new(),
            messages: VecDeque::new(),
        }
    }
}

impl<S: Scheme<B::Digest>, B: Block> Pending<S, B> {
    // Only prune advances are usable for height staleness checks. A pending
    // floor finalization does not carry the block height until the block is decoded.
    const fn height(&self) -> Option<Height> {
        self.prune
    }

    fn retain(&mut self) {
        let current = self.height();
        self.hints.retain(|height, _| Some(*height) > current);

        let hints = &self.hints;
        self.messages.retain(|message| match message {
            PendingMessage::Message(message) => {
                !message.response_closed() && !message.stale(current)
            }
            PendingMessage::HintFinalized(height) => hints.contains_key(height),
        });
    }

    fn set_floor(&mut self, finalization: Finalization<S, B::Digest>) {
        let round = finalization.round();
        if self
            .floor
            .as_ref()
            .is_some_and(|floor| floor.round() >= round)
        {
            return;
        }

        self.floor = Some(finalization);
    }

    fn prune(&mut self, height: Height) {
        let current = self.height();
        let prune = Some(height);
        if self.prune >= prune {
            return;
        }

        self.prune = self.prune.max(prune);
        if self.height() > current {
            self.retain();
        }
    }

    fn extend_hint_targets(
        pending: &mut NonEmptyVec<S::PublicKey>,
        targets: NonEmptyVec<S::PublicKey>,
    ) {
        for target in targets {
            if !pending.contains(&target) {
                pending.push(target);
            }
        }
    }

    fn hint_finalized(&mut self, height: Height, targets: NonEmptyVec<S::PublicKey>) {
        // The finalized height is already covered by the floor or prune point.
        let current = self.height();
        if current.is_some_and(|current| height <= current) {
            return;
        }

        match self.hints.entry(height) {
            Entry::Vacant(entry) => {
                entry.insert(targets);
                self.messages
                    .push_back(PendingMessage::HintFinalized(height));
            }
            Entry::Occupied(mut entry) => {
                Self::extend_hint_targets(entry.get_mut(), targets);
            }
        }
    }

    fn restore_hint(&mut self, height: Height, targets: NonEmptyVec<S::PublicKey>) {
        match self.hints.entry(height) {
            Entry::Vacant(entry) => {
                entry.insert(targets);
            }
            Entry::Occupied(mut entry) => {
                Self::extend_hint_targets(entry.get_mut(), targets);
            }
        }
        self.messages
            .push_front(PendingMessage::HintFinalized(height));
    }

    fn drain_one<F>(&mut self, message: Message<S, B>, push: &mut F) -> bool
    where
        F: FnMut(Message<S, B>) -> Option<Message<S, B>>,
    {
        // Receiver accepted; the message is consumed
        let Some(message) = push(message) else {
            return true;
        };

        // Receiver rejected; restore so the next drain retries from the same point
        match message {
            Message::SetFloor { finalization } => self.set_floor(finalization),
            Message::Prune { height } => self.prune(height),
            Message::HintFinalized { height, targets } => self.restore_hint(height, targets),
            message => self.messages.push_front(PendingMessage::Message(message)),
        }
        false
    }
}

impl<S: Scheme<B::Digest>, B: Block> Overflow<Message<S, B>> for Pending<S, B> {
    fn is_empty(&self) -> bool {
        self.floor.is_none()
            && self.prune.is_none()
            && self.hints.is_empty()
            && self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<S, B>) -> Option<Message<S, B>>,
    {
        // Drain floor and prune first so the actor advances its floor before
        // it sees the height-bounded reads that follow
        if let Some(finalization) = self.floor.take()
            && !self.drain_one(Message::SetFloor { finalization }, &mut push)
        {
            return;
        }
        if let Some(height) = self.prune.take()
            && !self.drain_one(Message::Prune { height }, &mut push)
        {
            return;
        }

        // Drain the remaining queued messages in FIFO order
        while let Some(pending) = self.messages.pop_front() {
            match pending {
                PendingMessage::Message(message) => {
                    if message.response_closed() {
                        continue;
                    }
                    if !self.drain_one(message, &mut push) {
                        break;
                    }
                }
                PendingMessage::HintFinalized(hint_height) => {
                    let Some(targets) = self.hints.remove(&hint_height) else {
                        continue;
                    };
                    let message = Message::HintFinalized {
                        height: hint_height,
                        targets,
                    };
                    if !self.drain_one(message, &mut push) {
                        break;
                    }
                }
            }
        }
    }
}

impl<S: Scheme<B::Digest>, B: Block> Policy for Message<S, B> {
    type Overflow = Pending<S, B>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        // A closed responder cannot be served
        if message.response_closed() {
            return;
        }
        match message {
            // Coalesce hints: a single entry per height with a unioned target set
            Self::HintFinalized { height, targets } => {
                overflow.hint_finalized(height, targets);
            }
            // Floors collapse to the highest round seen; prune collapses to
            // the highest height seen.
            Self::SetFloor { finalization } => {
                overflow.set_floor(finalization);
            }
            Self::Prune { height } => {
                overflow.prune(height);
            }
            // Queue if the new message is still useful
            message => {
                if message.stale(overflow.height()) {
                    return;
                }
                overflow
                    .messages
                    .push_back(PendingMessage::Message(message));
            }
        }
    }
}

/// A mailbox for sending messages to the marshal [Actor](crate::actor::Actor).
#[derive(Clone)]
pub struct Mailbox<S: Scheme<B::Digest>, B: Block> {
    sender: Sender<Message<S, B>>,
}

impl<S: Scheme<B::Digest>, B: Block> Mailbox<S, B> {
    /// Creates a new mailbox.
    pub(crate) const fn new(sender: Sender<Message<S, B>>) -> Self {
        Self { sender }
    }

    /// A request to retrieve the information about the highest finalized block.
    pub async fn get_info(
        &mut self,
        identifier: impl Into<Identifier<B::Digest>>,
    ) -> Option<(Height, B::Digest)> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetInfo {
            identifier: identifier.into(),
            response,
        });
        receiver.await.ok().flatten()
    }

    /// A best-effort attempt to retrieve a given block from local
    /// storage. It is not an indication to go fetch the block from the network.
    pub async fn get_block(&mut self, identifier: impl Into<Identifier<B::Digest>>) -> Option<B> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::GetBlock {
            identifier: identifier.into(),
            response,
        });
        receiver.await.ok().flatten()
    }

    /// A best-effort attempt to retrieve a given [Finalization] from local
    /// storage. It is not an indication to go fetch the [Finalization] from the network.
    pub async fn get_finalization(&mut self, height: Height) -> Option<Finalization<S, B::Digest>> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::GetFinalization { height, response });
        receiver.await.ok().flatten()
    }

    /// Retrieve the latest processed height.
    pub async fn get_processed_height(&self) -> Option<Height> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::GetProcessedHeight { response });
        receiver.await.ok().flatten()
    }

    /// Hints that a finalization should be fetched from the network if not available locally.
    ///
    /// This is fire-and-forget: the finalization will be stored in syncer and delivered
    /// via the normal finalization flow when available.
    ///
    /// The hint is advisory catch-up input, so callers running a control loop
    /// that must stay responsive (the orchestrator processes epoch Enter/Exit on
    /// the same loop) must not park on a full syncer mailbox. Enqueueing is
    /// non-blocking: when the mailbox is full, hints are coalesced per height
    /// (with unioned target sets) in the overflow state instead of blocking or
    /// being lost.
    pub fn hint_finalized(&mut self, height: Height, targets: NonEmptyVec<S::PublicKey>) {
        let _ = self
            .sender
            .enqueue(Message::HintFinalized { height, targets });
    }

    /// A request to retrieve a block by its commitment.
    ///
    /// If the block is found available locally, the block will be returned immediately.
    ///
    /// If the block is not available locally, the request will be registered and the caller will
    /// be notified when the block is available. If the block is not finalized, it's possible that
    /// it may never become available.
    ///
    /// The oneshot receiver should be dropped to cancel the subscription.
    pub fn subscribe(
        &mut self,
        round: Option<Round>,
        commitment: B::Digest,
    ) -> oneshot::Receiver<B> {
        let (response, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Subscribe {
            round,
            commitment,
            response,
        });
        receiver
    }

    /// Hint that peers may have the block notarized at `round`.
    ///
    /// This issues a round-bound resolver request without registering a new
    /// block subscriber. The `commitment` is only used to skip the request when
    /// the block is already available locally.
    pub fn hint_notarized(&self, round: Round, commitment: B::Digest) {
        let _ = self
            .sender
            .enqueue(Message::HintNotarized { round, commitment });
    }

    /// Returns the verified block previously persisted for `round`, if any.
    pub async fn get_verified(&self, round: Round) -> Option<B> {
        let (response, receiver) = oneshot::channel();
        let _ = self
            .sender
            .enqueue(Message::GetVerified { round, response });
        receiver.await.ok().flatten()
    }

    /// Returns an [AncestorStream] over the ancestry of a given block, leading up to genesis.
    ///
    /// If the starting block is not found, `None` is returned.
    pub async fn ancestry(
        &mut self,
        (start_round, start_commitment): (Option<Round>, B::Digest),
    ) -> Option<AncestorStream<S, B>> {
        self.subscribe(start_round, start_commitment)
            .await
            .ok()
            .map(|block| AncestorStream::new(self.clone(), [block]))
    }

    /// Proposed requests that a proposed block is sent to all peers.
    ///
    /// Returns after the block is durably stored and broadcast.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn proposed(&mut self, round: Round, block: B) -> bool {
        let (ack, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Proposed {
            round,
            block,
            ack: Some(ack),
        });
        receiver.await.is_ok()
    }

    /// Forward a block to a set of recipients.
    pub fn forward(
        &self,
        round: Round,
        commitment: B::Digest,
        recipients: Recipients<S::PublicKey>,
    ) -> Feedback {
        self.sender.enqueue(Message::Forward {
            round,
            commitment,
            recipients,
        })
    }

    /// Notifies the actor that a block has been verified.
    ///
    /// Returns after the block is durably stored.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn verified(&mut self, round: Round, block: B) -> bool {
        let (ack, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Verified {
            round,
            block,
            ack: Some(ack),
        });
        receiver.await.is_ok()
    }

    /// Notifies the actor that a block has been certified.
    ///
    /// Returns after the block is durably stored.
    #[must_use = "callers must consider block durability before proceeding"]
    pub async fn certified(&mut self, round: Round, block: B) -> bool {
        let (ack, receiver) = oneshot::channel();
        let _ = self.sender.enqueue(Message::Certified {
            round,
            block,
            ack: Some(ack),
        });
        receiver.await.is_ok()
    }

    /// Attempts to set the sync starting point from a finalized commitment.
    ///
    /// If the verified finalization advances the current floor, the syncer
    /// anchors on its block, prunes below it, then syncs and delivers blocks
    /// starting at the floor height. Stale or superseded floors may be ignored.
    ///
    /// To prune data without changing the sync starting point, use
    /// [`Self::prune`] instead.
    pub fn set_floor(&mut self, finalization: Finalization<S, B::Digest>) {
        let _ = self.sender.enqueue(Message::SetFloor { finalization });
    }

    /// Prunes finalized blocks and certificates below the given height.
    ///
    /// Unlike [`Self::set_floor`], this does not affect the sync starting point.
    /// The height must be at or below the current floor (last processed height),
    /// otherwise the prune request is ignored.
    pub fn prune(&mut self, height: Height) {
        let _ = self.sender.enqueue(Message::Prune { height });
    }

    /// Notifies the actor of a verified [`Finalization`].
    ///
    /// This is a trusted call that injects a finalization directly into marshal. The
    /// finalization is expected to have already been verified by the caller.
    pub fn finalization(&mut self, finalization: Finalization<S, B::Digest>) {
        let _ = self.sender.enqueue(Message::Finalization { finalization });
    }
}

impl<S: Scheme<B::Digest>, B: Block> Reporter for Mailbox<S, B> {
    type Activity = Activity<S, B::Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let message = match activity {
            Activity::Notarization(notarization) => Message::Notarization { notarization },
            Activity::Finalization(finalization) => Message::Finalization { finalization },
            _ => return Feedback::Ok,
        };
        self.sender.enqueue(message)
    }
}

/// Returns a boxed subscription future for a block.
#[inline]
fn subscribe_block_future<S: Scheme<B::Digest>, B: Block>(
    mut marshal: Mailbox<S, B>,
    commitment: B::Digest,
) -> BoxFuture<'static, Option<B>> {
    async move {
        let receiver = marshal.subscribe(None, commitment);
        receiver.await.ok()
    }
    .boxed()
}

/// Yields the ancestors of a block while prefetching parents, _not_ including the genesis block.
///
/// TODO(clabby): Once marshal can also yield the genesis block, this stream should end
/// at block height 0 rather than 1.
#[pin_project]
pub struct AncestorStream<S: Scheme<B::Digest>, B: Block> {
    marshal: Mailbox<S, B>,
    buffered: Vec<B>,
    #[pin]
    pending: FuturesOrdered<BoxFuture<'static, Option<B>>>,
}

impl<S: Scheme<B::Digest>, B: Block> AncestorStream<S, B> {
    /// Creates a new [AncestorStream] starting from the given ancestry.
    ///
    /// # Panics
    ///
    /// Panics if the initial blocks are not contiguous in height.
    pub(crate) fn new(marshal: Mailbox<S, B>, initial: impl IntoIterator<Item = B>) -> Self {
        let mut buffered = initial.into_iter().collect::<Vec<B>>();
        buffered.sort_by_key(|b| b.height());

        // Check that the initial blocks are contiguous in height.
        buffered.windows(2).for_each(|window| {
            assert_eq!(
                window[0].height().next(),
                window[1].height(),
                "initial blocks must be contiguous in height"
            );
        });

        Self {
            marshal,
            buffered,
            pending: FuturesOrdered::new(),
        }
    }
}

impl<S: Scheme<B::Digest>, B: Block> Stream for AncestorStream<S, B> {
    type Item = B;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Because marshal cannot currently yield the genesis block, we stop at height 1.
        let end_bound = Height::new(1);

        let mut this = self.project();

        // If a result has been buffered, return it and queue the parent fetch if needed.
        if let Some(block) = this.buffered.pop() {
            let height = block.height();
            let should_fetch_parent = height > end_bound && this.buffered.is_empty();
            if should_fetch_parent {
                let parent_commitment = block.parent();
                let future = subscribe_block_future(this.marshal.clone(), parent_commitment);
                this.pending.push_back(future);

                // Explicitly poll the pending futures to kick off the fetch. If it's already ready,
                // buffer it for the next poll.
                if let Poll::Ready(Some(Some(block))) = this.pending.as_mut().poll_next(cx) {
                    this.buffered.push(block);
                }
            }

            return Poll::Ready(Some(block));
        }

        match this.pending.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) | Poll::Ready(Some(None)) => Poll::Ready(None),
            Poll::Ready(Some(Some(block))) => {
                let height = block.height();
                let should_fetch_parent = height > end_bound;
                if should_fetch_parent {
                    let parent_commitment = block.parent();
                    let future = subscribe_block_future(this.marshal.clone(), parent_commitment);
                    this.pending.push_back(future);

                    // Explicitly poll the pending futures to kick off the fetch. If it's already ready,
                    // buffer it for the next poll.
                    if let Poll::Ready(Some(Some(block))) = this.pending.as_mut().poll_next(cx) {
                        this.buffered.push(block);
                    }
                }

                Poll::Ready(Some(block))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::block::Block as MockBlock;
    use commonware_consensus::simplex::scheme::ed25519 as ed_scheme;
    use commonware_cryptography::{Signer, ed25519, sha256};
    use commonware_math::algebra::Random;
    use rand::{SeedableRng, rngs::StdRng};

    type TestScheme = ed_scheme::Scheme;
    type TestBlock = MockBlock<sha256::Digest>;
    type TestMessage = Message<TestScheme, TestBlock>;
    type TestPending = Pending<TestScheme, TestBlock>;

    fn target(seed: u64) -> ed25519::PublicKey {
        ed25519::PrivateKey::random(&mut StdRng::seed_from_u64(seed)).public_key()
    }

    // The orchestrator drives hint_finalized on the same loop that processes
    // epoch Enter/Exit, so it must never block on a full syncer mailbox. The
    // overflow policy coalesces hints per height (with unioned target sets)
    // instead of blocking or dropping them silently.
    #[test]
    fn hint_finalized_coalesces_in_overflow() {
        let mut overflow = TestPending::default();

        let first = target(0);
        let second = target(1);

        // Two hints for the same height coalesce into one entry with a
        // unioned target set.
        TestMessage::handle(
            &mut overflow,
            Message::HintFinalized {
                height: Height::new(1),
                targets: NonEmptyVec::new(first.clone()),
            },
        );
        TestMessage::handle(
            &mut overflow,
            Message::HintFinalized {
                height: Height::new(1),
                targets: NonEmptyVec::new(second.clone()),
            },
        );

        let mut drained = Vec::new();
        Overflow::drain(&mut overflow, |message| {
            drained.push(message);
            None
        });

        assert_eq!(drained.len(), 1);
        match drained.pop() {
            Some(Message::HintFinalized { height, targets }) => {
                assert_eq!(height, Height::new(1));
                let targets: Vec<_> = targets.into_iter().collect();
                assert_eq!(targets, vec![first, second]);
            }
            _ => panic!("expected a coalesced HintFinalized message"),
        }
        assert!(overflow.is_empty());
    }

    // Prune requests collapse to the highest height and staleness-check
    // queued hints so a full mailbox cannot accumulate unbounded state.
    #[test]
    fn prune_collapses_and_drops_stale_hints() {
        let mut overflow = TestPending::default();

        TestMessage::handle(
            &mut overflow,
            Message::HintFinalized {
                height: Height::new(1),
                targets: NonEmptyVec::new(target(0)),
            },
        );
        TestMessage::handle(
            &mut overflow,
            Message::HintFinalized {
                height: Height::new(5),
                targets: NonEmptyVec::new(target(1)),
            },
        );
        TestMessage::handle(
            &mut overflow,
            Message::Prune {
                height: Height::new(2),
            },
        );
        TestMessage::handle(
            &mut overflow,
            Message::Prune {
                height: Height::new(3),
            },
        );

        let mut drained = Vec::new();
        Overflow::drain(&mut overflow, |message| {
            drained.push(message);
            None
        });

        // One collapsed prune (highest height) and only the still-useful hint.
        assert_eq!(drained.len(), 2);
        assert!(matches!(
            drained[0],
            Message::Prune { height } if height == Height::new(3)
        ));
        assert!(matches!(
            drained[1],
            Message::HintFinalized { height, .. } if height == Height::new(5)
        ));
        assert!(overflow.is_empty());
    }
}
