use crate::Update;
use commonware_consensus::simplex::signing_scheme::Scheme;
use commonware_consensus::{Block, Reporter};
use commonware_utils::Acknowledgement;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

/// A mock application that stores finalized blocks.
#[derive(Clone)]
pub struct Application<B: Block, S: Scheme> {
    blocks: Arc<Mutex<BTreeMap<u64, B>>>,
    #[allow(clippy::type_complexity)]
    tip: Arc<Mutex<Option<(u64, B::Commitment)>>>,
    _phantom: std::marker::PhantomData<S>,
}

impl<B: Block, S: Scheme> Default for Application<B, S> {
    fn default() -> Self {
        Self {
            blocks: Default::default(),
            tip: Default::default(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<B: Block, S: Scheme> Application<B, S> {
    /// Returns the finalized blocks.
    pub fn blocks(&self) -> BTreeMap<u64, B> {
        self.blocks.lock().unwrap().clone()
    }

    /// Returns the tip.
    pub fn tip(&self) -> Option<(u64, B::Commitment)> {
        *self.tip.lock().unwrap()
    }
}

impl<B: Block, S: Scheme> Reporter for Application<B, S> {
    type Activity = Update<B, S>;

    async fn report(&mut self, activity: Self::Activity) {
        match activity {
            Update::Tip(height, commitment) => {
                *self.tip.lock().unwrap() = Some((height, commitment));
            }
            Update::FinalizedBlock((block, _), ack_tx) => {
                self.blocks.lock().unwrap().insert(block.height(), block);
                ack_tx.acknowledge();
            }
            Update::NotarizedBlock(_block) => {
                // Mock application ignores notarized blocks
            }
        }
    }
}
