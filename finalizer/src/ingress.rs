use futures::{
    SinkExt as _,
    channel::{mpsc, oneshot},
};
use summit_types::{
    BlockAuxData,
    checkpoint::Checkpoint,
    consensus_state_query::{ConsensusStateRequest, ConsensusStateResponse},
};

pub enum FinalizerMessage {
    NotifyAtHeight {
        height: u64,
        response: oneshot::Sender<()>,
    },
    GetAuxData {
        height: u64,
        response: oneshot::Sender<BlockAuxData>,
    },
    QueryState {
        request: ConsensusStateRequest,
        response: oneshot::Sender<ConsensusStateResponse>,
    },
}

#[derive(Clone)]
pub struct FinalizerMailbox {
    sender: mpsc::Sender<FinalizerMessage>,
}

impl FinalizerMailbox {
    pub fn new(sender: mpsc::Sender<FinalizerMessage>) -> Self {
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
}
