use crate::PublicKey;
use crate::checkpoint::Checkpoint;
use futures::SinkExt;
use futures::channel::{mpsc, oneshot};

pub enum ConsensusStateRequest {
    GetCheckpoint,
    GetLatestHeight,
    GetValidatorBalance(PublicKey),
}

pub enum ConsensusStateResponse {
    Checkpoint(Option<Checkpoint>),
    LatestHeight(u64),
    ValidatorBalance(Option<u64>),
}

/// Used to send queries to the application finalizer to query the consensus state.
#[derive(Clone, Debug)]
pub struct ConsensusStateQuery {
    sender: mpsc::Sender<(
        ConsensusStateRequest,
        oneshot::Sender<ConsensusStateResponse>,
    )>,
}

impl ConsensusStateQuery {
    pub fn new(
        buffer_size: usize,
    ) -> (
        ConsensusStateQuery,
        mpsc::Receiver<(
            ConsensusStateRequest,
            oneshot::Sender<ConsensusStateResponse>,
        )>,
    ) {
        let (sender, receiver) = mpsc::channel(buffer_size);
        (ConsensusStateQuery { sender }, receiver)
    }

    pub async fn get_latest_checkpoint_mut(&mut self) -> Option<Checkpoint> {
        let (tx, rx) = oneshot::channel();
        let req = ConsensusStateRequest::GetCheckpoint;
        let _ = self.sender.send((req, tx)).await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::Checkpoint(maybe_checkpoint) = res else {
            unreachable!("request and response variants must match");
        };
        maybe_checkpoint
    }

    pub async fn get_latest_checkpoint(&self) -> Option<Checkpoint> {
        let (tx, rx) = oneshot::channel();
        let req = ConsensusStateRequest::GetCheckpoint;
        let _ = self.sender.clone().send((req, tx)).await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::Checkpoint(maybe_checkpoint) = res else {
            unreachable!("request and response variants must match");
        };
        maybe_checkpoint
    }

    pub async fn get_latest_height(&self) -> u64 {
        let (tx, rx) = oneshot::channel();
        let req = ConsensusStateRequest::GetLatestHeight;
        let _ = self.sender.clone().send((req, tx)).await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::LatestHeight(height) = res else {
            unreachable!("request and response variants must match");
        };
        height
    }

    pub async fn get_validator_balance(&self, public_key: PublicKey) -> Option<u64> {
        let (tx, rx) = oneshot::channel();
        let req = ConsensusStateRequest::GetValidatorBalance(public_key);
        let _ = self.sender.clone().send((req, tx)).await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::ValidatorBalance(balance) = res else {
            unreachable!("request and response variants must match");
        };
        balance
    }
}
