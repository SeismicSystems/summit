//! Membership filter for consensus-channel ingress.
//!
//! Summit tracks non-voting identities (joining validators and observer-derived
//! keys) as secondary P2P peers so they can connect and follow the chain. The
//! authenticated network does not gate per-channel sends by peer role, and the
//! epoch multiplexer drops on a full subchannel via `try_send` BEFORE Simplex
//! validates sender membership. A non-voting peer can therefore fill a bounded
//! validator-only consensus subchannel and starve honest validator messages
//! (an epoch-liveness DoS) without holding any BLS voting power.
//!
//! [`CommitteeFilteredReceiver`] wraps a consensus-channel [`Receiver`] and drops
//! a message whose sender is not in the active committee of the epoch
//! (subchannel) it targets, BEFORE it reaches the bounded subchannel. Messages
//! for epochs the orchestrator has NOT entered are passed through untouched: on
//! the `pending` channel those reach the mux backup and drive `hint_finalized`
//! catch-up from peers ahead of us, so they must not be filtered against our
//! (possibly stale) committee view.

use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::sync::{Arc, RwLock};

use commonware_consensus::types::Epoch;
use commonware_p2p::{Channel, Message, Receiver, utils::mux};
use summit_types::PublicKey;
use tracing::trace;

/// Active committees keyed by entered epoch: the node keys allowed to send on
/// that epoch's consensus subchannels. Written by the orchestrator loop on epoch
/// `Enter`/`Exit`, read by the ingress filters running inside the mux tasks.
pub type ActiveCommittees = Arc<RwLock<BTreeMap<Epoch, HashSet<PublicKey>>>>;

/// Whether a message from `from`, targeting `subchannel` (an epoch), is admitted
/// onto the consensus channels.
///
/// - Entered epoch: only that epoch's committee may send (protects the bounded
///   subchannel capacity from non-voting peers).
/// - Not-yet-entered (ahead) epoch: admit, so the mux backup / `hint_finalized`
///   catch-up path keeps working regardless of our current committee view.
fn admit(
    committees: &BTreeMap<Epoch, HashSet<PublicKey>>,
    subchannel: Channel,
    from: &PublicKey,
) -> bool {
    match committees.get(&Epoch::new(subchannel)) {
        Some(committee) => committee.contains(from),
        None => true,
    }
}

pub struct CommitteeFilteredReceiver<R> {
    inner: R,
    committees: ActiveCommittees,
    channel: &'static str,
}

impl<R> CommitteeFilteredReceiver<R> {
    pub fn new(inner: R, committees: ActiveCommittees, channel: &'static str) -> Self {
        Self {
            inner,
            committees,
            channel,
        }
    }
}

impl<R: fmt::Debug> fmt::Debug for CommitteeFilteredReceiver<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitteeFilteredReceiver")
            .field("channel", &self.channel)
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<R> Receiver for CommitteeFilteredReceiver<R>
where
    R: Receiver<PublicKey = PublicKey>,
{
    type Error = R::Error;
    type PublicKey = PublicKey;

    async fn recv(&mut self) -> Result<Message<Self::PublicKey>, Self::Error> {
        loop {
            let (from, bytes) = self.inner.recv().await?;

            // Peek the target subchannel (epoch). `parse` consumes the varint
            // prefix, so peek a cheap clone and forward the original bytes for
            // the mux to re-parse.
            let admitted = match mux::parse(bytes.clone()) {
                Ok((subchannel, _)) => {
                    let committees = self.committees.read().expect("committees lock poisoned");
                    admit(&committees, subchannel, &from)
                }
                // Malformed (no subchannel prefix): let the mux reject it.
                Err(_) => true,
            };

            if admitted {
                return Ok((from, bytes));
            }
            #[cfg(feature = "prom")]
            metrics::counter!("consensus_ingress_rejected", "channel" => self.channel).increment(1);
            trace!(
                channel = self.channel,
                ?from,
                "dropped consensus ingress from non-committee sender"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Signer, ed25519};

    fn key(seed: u64) -> PublicKey {
        ed25519::PrivateKey::from_seed(seed).public_key()
    }

    #[test]
    fn entered_epoch_admits_only_its_committee() {
        let member = key(0);
        let outsider = key(1);
        let mut committees = BTreeMap::new();
        committees.insert(Epoch::new(7), HashSet::from([member.clone()]));

        // A committee member sending on its own epoch is admitted.
        assert!(admit(&committees, 7, &member));
        // A non-member (joining/observer/bootstrapper) on an entered epoch is
        // dropped before it can consume that epoch's bounded subchannel.
        assert!(!admit(&committees, 7, &outsider));
    }

    #[test]
    fn member_of_other_entered_epoch_is_not_admitted() {
        // Per-epoch, not union: a validator of epoch 7 cannot send on epoch 8's
        // subchannel (Simplex would reject it anyway; we save the capacity).
        let member = key(0);
        let mut committees = BTreeMap::new();
        committees.insert(Epoch::new(7), HashSet::from([member.clone()]));
        committees.insert(Epoch::new(8), HashSet::from([key(2)]));
        assert!(!admit(&committees, 8, &member));
    }

    #[test]
    fn unentered_epoch_passes_through_for_catchup() {
        // Messages for an epoch we have not entered (e.g. a peer ahead of us)
        // are passed through so the mux backup / hint_finalized catch-up works,
        // even from a sender not in any committee we currently track.
        let committees = BTreeMap::new();
        assert!(admit(&committees, 99, &key(3)));

        let mut committees = BTreeMap::new();
        committees.insert(Epoch::new(7), HashSet::from([key(0)]));
        assert!(admit(&committees, 99, &key(3)));
    }
}
