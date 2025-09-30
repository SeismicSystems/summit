use crate::checkpoint::Checkpoint;
use tokio::sync::{mpsc, oneshot};

pub enum ConsensusStateRequest {
    GetCheckpoint,
}

pub enum ConsensusStateResponse {
    Checkpoint(Option<Checkpoint>),
}

pub fn new(buffer_size: usize) -> (ConsensusStateQuery, ConsensusStateQueryMailbox) {
    let (sender, receiver) = mpsc::channel(buffer_size);
    (
        ConsensusStateQuery { sender },
        ConsensusStateQueryMailbox { receiver },
    )
}

/// Receives queries about the consensus state..
#[derive(Debug)]
pub struct ConsensusStateQueryMailbox {
    receiver: mpsc::Receiver<(
        ConsensusStateRequest,
        oneshot::Sender<ConsensusStateResponse>,
    )>,
}

impl ConsensusStateQueryMailbox {}

/// Used to send queries to the application finalizer to query the consensus state.
#[derive(Clone, Debug)]
pub struct ConsensusStateQuery {
    sender: mpsc::Sender<(
        ConsensusStateRequest,
        oneshot::Sender<ConsensusStateResponse>,
    )>,
}

impl ConsensusStateQuery {
    pub async fn get_latest_checkpoint(&self) -> Option<Checkpoint> {
        let (tx, rx) = oneshot::channel();
        let req = ConsensusStateRequest::GetCheckpoint;
        let _ = self.sender.send((req, tx)).await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::Checkpoint(maybe_checkpoint) = res;
        maybe_checkpoint
    }
}
