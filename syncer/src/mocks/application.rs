use crate::Update;
use commonware_actor::Feedback;
use commonware_consensus::simplex::scheme::Scheme;
use commonware_consensus::{Block, Reporter};
use commonware_utils::Acknowledgement;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordedUpdate<D> {
    Finalized(D),
    Notarized(D),
}

/// A mock application that stores finalized blocks.
#[derive(Clone)]
pub struct Application<B: Block, S: Scheme<B::Digest>> {
    blocks: Arc<Mutex<BTreeMap<u64, B>>>,
    updates: Arc<Mutex<Vec<RecordedUpdate<B::Digest>>>>,
    #[allow(clippy::type_complexity)]
    tip: Arc<Mutex<Option<(u64, B::Digest)>>>,
    _phantom: std::marker::PhantomData<S>,
}

impl<B: Block, S: Scheme<B::Digest>> Default for Application<B, S> {
    fn default() -> Self {
        Self {
            blocks: Default::default(),
            updates: Default::default(),
            tip: Default::default(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<B: Block, S: Scheme<B::Digest>> Application<B, S> {
    /// Returns the finalized blocks.
    pub fn blocks(&self) -> BTreeMap<u64, B> {
        self.blocks.lock().unwrap().clone()
    }

    /// Returns the tip.
    pub fn tip(&self) -> Option<(u64, B::Digest)> {
        *self.tip.lock().unwrap()
    }

    /// Returns finalized and notarized block updates in report order.
    pub fn updates(&self) -> Vec<RecordedUpdate<B::Digest>> {
        self.updates.lock().unwrap().clone()
    }
}

impl<B: Block, S: Scheme<B::Digest>> Reporter for Application<B, S> {
    type Activity = Update<B, S>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        match activity {
            Update::Tip(height, commitment) => {
                *self.tip.lock().unwrap() = Some((height, commitment));
            }
            Update::FinalizedBlock((block, _), ack_tx) => {
                self.updates
                    .lock()
                    .unwrap()
                    .push(RecordedUpdate::Finalized(block.digest()));
                self.blocks
                    .lock()
                    .unwrap()
                    .insert(block.height().get(), block);
                ack_tx.acknowledge();
            }
            Update::NotarizedBlock(block) => {
                self.updates
                    .lock()
                    .unwrap()
                    .push(RecordedUpdate::Notarized(block.digest()));
            }
            Update::Fault(_) => {}
        }
        Feedback::Ok
    }
}
