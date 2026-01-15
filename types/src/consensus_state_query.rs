use crate::account::ValidatorAccount;
use crate::checkpoint::Checkpoint;
use crate::{Block, FinalizedHeader, PublicKey};
use commonware_cryptography::certificate::Scheme;
use futures::SinkExt;
use futures::channel::{mpsc, oneshot};

#[allow(clippy::large_enum_variant)]
pub enum ConsensusStateRequest {
    GetLatestCheckpoint,
    GetCheckpoint(u64),
    GetLatestHeight,
    GetLatestEpoch,
    GetValidatorBalance(PublicKey),
    GetValidatorAccount(PublicKey),
    GetFinalizedHeader(u64),
}

pub enum ConsensusStateResponse<S: Scheme> {
    LatestCheckpoint((Option<(Checkpoint, Block)>, u64)), // ((Checkpoint,LastBlock), Epoch#)
    Checkpoint(Option<(Checkpoint, Block)>),
    LatestHeight(u64),
    LatestEpoch(u64),
    ValidatorBalance(Option<u64>),
    ValidatorAccount(Option<ValidatorAccount>),
    FinalizedHeader(Option<FinalizedHeader<S>>),
}

/// Used to send queries to the application finalizer to query the consensus state.
#[derive(Clone, Debug)]
pub struct ConsensusStateQuery<S: Scheme> {
    sender: mpsc::Sender<(
        ConsensusStateRequest,
        oneshot::Sender<ConsensusStateResponse<S>>,
    )>,
}

#[allow(clippy::type_complexity)]
impl<S: Scheme> ConsensusStateQuery<S> {
    pub fn new(
        buffer_size: usize,
    ) -> (
        ConsensusStateQuery<S>,
        mpsc::Receiver<(
            ConsensusStateRequest,
            oneshot::Sender<ConsensusStateResponse<S>>,
        )>,
    ) {
        let (sender, receiver) = mpsc::channel(buffer_size);
        (ConsensusStateQuery { sender }, receiver)
    }

    pub async fn get_latest_checkpoint_mut(&mut self) -> (Option<(Checkpoint, Block)>, u64) {
        let (tx, rx) = oneshot::channel();
        let req = ConsensusStateRequest::GetLatestCheckpoint;
        let _ = self.sender.send((req, tx)).await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::LatestCheckpoint(maybe_checkpoint) = res else {
            unreachable!("request and response variants must match");
        };
        maybe_checkpoint
    }

    pub async fn get_latest_checkpoint(&self) -> (Option<(Checkpoint, Block)>, u64) {
        let (tx, rx) = oneshot::channel();
        let req = ConsensusStateRequest::GetLatestCheckpoint;
        let _ = self.sender.clone().send((req, tx)).await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::LatestCheckpoint(maybe_checkpoint) = res else {
            unreachable!("request and response variants must match");
        };
        maybe_checkpoint
    }

    pub async fn get_checkpoint(&self, epoch: u64) -> Option<(Checkpoint, Block)> {
        let (tx, rx) = oneshot::channel();
        let req = ConsensusStateRequest::GetCheckpoint(epoch);
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

    pub async fn get_latest_epoch(&self) -> u64 {
        let (tx, rx) = oneshot::channel();
        let req = ConsensusStateRequest::GetLatestEpoch;
        let _ = self.sender.clone().send((req, tx)).await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::LatestEpoch(epoch) = res else {
            unreachable!("request and response variants must match");
        };
        epoch
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

    pub async fn get_finalized_header(&self, height: u64) -> Option<FinalizedHeader<S>> {
        let (tx, rx) = oneshot::channel();
        let req = ConsensusStateRequest::GetFinalizedHeader(height);
        let _ = self.sender.clone().send((req, tx)).await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");

        let ConsensusStateResponse::FinalizedHeader(header) = res else {
            unreachable!("request and response variants must match");
        };

        header
    }
}
