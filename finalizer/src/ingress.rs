use commonware_consensus::simplex::signing_scheme::Scheme;
use commonware_consensus::{Block as ConsensusBlock, Reporter};
use commonware_cryptography::Committable;
use futures::{
    SinkExt as _,
    channel::{mpsc, oneshot},
};
use summit_syncer::Update;
use summit_types::{
    Block, BlockAuxData, PublicKey,
    checkpoint::Checkpoint,
    consensus_state_query::{ConsensusStateRequest, ConsensusStateResponse},
};

#[allow(clippy::large_enum_variant)]
pub enum FinalizerMessage<S: Scheme, B: ConsensusBlock + Committable = Block> {
    NotifyAtHeight {
        height: u64,
        response: oneshot::Sender<()>,
    },
    GetAuxData {
        height: u64,
        response: oneshot::Sender<BlockAuxData>,
    },
    GetEpochGenesisHash {
        epoch: u64,
        response: oneshot::Sender<[u8; 32]>,
    },
    QueryState {
        request: ConsensusStateRequest,
        response: oneshot::Sender<ConsensusStateResponse>,
    },
    SyncerUpdate {
        update: Update<B, S>,
    },
}

#[derive(Clone)]
pub struct FinalizerMailbox<S: Scheme, B: ConsensusBlock + Committable = Block> {
    sender: mpsc::Sender<FinalizerMessage<S, B>>,
}

impl<S: Scheme, B: ConsensusBlock + Committable> FinalizerMailbox<S, B> {
    pub fn new(sender: mpsc::Sender<FinalizerMessage<S, B>>) -> Self {
        Self { sender }
    }

    pub async fn notify_at_height(&mut self, height: u64) -> oneshot::Receiver<()> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(FinalizerMessage::NotifyAtHeight { height, response })
            .await
            .expect("Unable to send to main Finalizer loop");

        receiver
    }

    pub async fn get_aux_data(&mut self, height: u64) -> oneshot::Receiver<BlockAuxData> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(FinalizerMessage::GetAuxData { height, response })
            .await
            .expect("Unable to send to main Finalizer loop");

        receiver
    }

    pub async fn get_epoch_genesis_hash(&mut self, epoch: u64) -> oneshot::Receiver<[u8; 32]> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(FinalizerMessage::GetEpochGenesisHash { epoch, response })
            .await
            .expect("Unable to send to main Finalizer loop");

        receiver
    }

    pub async fn get_latest_checkpoint(&mut self) -> Option<Checkpoint> {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetCheckpoint;
        let _ = self
            .sender
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");

        let ConsensusStateResponse::Checkpoint(maybe_checkpoint) = res else {
            unreachable!("request and response variants must match");
        };

        maybe_checkpoint
    }

    pub async fn get_latest_height(&self) -> u64 {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetLatestHeight;
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::LatestHeight(height) = res else {
            unreachable!("request and response variants must match");
        };
        height
    }

    pub async fn get_validator_balance(&self, public_key: PublicKey) -> Option<u64> {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetValidatorBalance(public_key);
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::ValidatorBalance(balance) = res else {
            unreachable!("request and response variants must match");
        };
        balance
    }
}

impl<S: Scheme, B: ConsensusBlock + Committable> Reporter for FinalizerMailbox<S, B> {
    type Activity = Update<B, S>;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender
            .send(FinalizerMessage::SyncerUpdate { update: activity })
            .await
            .expect("Unable to send syncer update to Finalizer");
    }
}
