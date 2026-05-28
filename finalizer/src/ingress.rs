use commonware_consensus::simplex::scheme::Scheme;
use commonware_consensus::{Block as ConsensusBlock, Reporter};
use futures::{
    SinkExt as _,
    channel::{mpsc, oneshot},
};
use summit_syncer::Update;
use summit_types::FinalizedHeader;
use summit_types::account::ValidatorAccount;
use summit_types::{
    Block, BlockAuxData, Digest, PublicKey,
    checkpoint::Checkpoint,
    consensus_state_query::{ConsensusStateRequest, ConsensusStateResponse},
};

#[allow(clippy::large_enum_variant)]
pub enum FinalizerMessage<S: Scheme<B::Digest>, B: ConsensusBlock = Block> {
    NotifyAtHeight {
        height: u64,
        block_digest: Digest,
        response: oneshot::Sender<bool>,
    },
    GetAuxData {
        height: u64,
        parent_digest: Digest,
        response: oneshot::Sender<Option<BlockAuxData>>,
    },
    GetEpochGenesisHash {
        epoch: u64,
        response: oneshot::Sender<[u8; 32]>,
    },
    QueryState {
        request: ConsensusStateRequest,
        response: oneshot::Sender<ConsensusStateResponse<S>>,
    },
    SyncerUpdate {
        update: Update<B, S>,
    },
}

#[derive(Clone)]
pub struct FinalizerMailbox<S: Scheme<B::Digest>, B: ConsensusBlock = Block> {
    sender: mpsc::Sender<FinalizerMessage<S, B>>,
}

impl<S: Scheme<B::Digest>, B: ConsensusBlock> FinalizerMailbox<S, B> {
    pub fn new(sender: mpsc::Sender<FinalizerMessage<S, B>>) -> Self {
        Self { sender }
    }

    pub async fn notify_at_height(
        &mut self,
        height: u64,
        block_digest: Digest,
    ) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(FinalizerMessage::NotifyAtHeight {
                height,
                block_digest,
                response,
            })
            .await
            .expect("Unable to send to main Finalizer loop");

        receiver
    }

    pub async fn get_aux_data(
        &mut self,
        height: u64,
        parent_digest: Digest,
    ) -> oneshot::Receiver<Option<BlockAuxData>> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(FinalizerMessage::GetAuxData {
                height,
                parent_digest,
                response,
            })
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

    pub async fn get_latest_checkpoint(&mut self) -> (Option<(Checkpoint, Block)>, u64) {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetLatestCheckpoint;
        let _ = self
            .sender
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");

        let ConsensusStateResponse::LatestCheckpoint(maybe_checkpoint) = res else {
            unreachable!("request and response variants must match");
        };

        maybe_checkpoint
    }

    pub async fn get_checkpoint(&mut self, epoch: u64) -> Option<(Checkpoint, Block)> {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetCheckpoint(epoch);
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

    pub async fn get_finalized_header(&mut self, epoch: u64) -> Option<FinalizedHeader<S>> {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetFinalizedHeader(epoch);

        let _ = self
            .sender
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");

        let ConsensusStateResponse::FinalizedHeader(header) = res else {
            unreachable!("request and response variants must match");
        };

        header
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

    pub async fn get_latest_epoch(&self) -> u64 {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetLatestEpoch;
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::LatestEpoch(epoch) = res else {
            unreachable!("request and response variants must match");
        };
        epoch
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

    // Added for testing
    pub async fn get_validator_account(&self, public_key: PublicKey) -> Option<ValidatorAccount> {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetValidatorAccount(public_key);
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::ValidatorAccount(account) = res else {
            unreachable!("request and response variants must match");
        };
        account
    }

    pub async fn get_minimum_stake(&self) -> u64 {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetMinimumStake;
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::MinimumStake(stake) = res else {
            unreachable!("request and response variants must match");
        };
        stake
    }

    pub async fn get_maximum_stake(&self) -> u64 {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetMaximumStake;
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::MaximumStake(stake) = res else {
            unreachable!("request and response variants must match");
        };
        stake
    }

    pub async fn get_epoch_length(&self) -> u64 {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetEpochLength;
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::EpochLength(length) = res else {
            unreachable!("request and response variants must match");
        };
        length
    }

    pub async fn get_allowed_timestamp_future(&self) -> u64 {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetAllowedTimestampFuture;
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::AllowedTimestampFuture(ms) = res else {
            unreachable!("request and response variants must match");
        };
        ms
    }

    pub async fn get_treasury_address(&self) -> alloy_primitives::Address {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetTreasuryAddress;
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::TreasuryAddress(address) = res else {
            unreachable!("request and response variants must match");
        };
        address
    }

    pub async fn get_max_deposits_per_epoch(&self) -> u64 {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetMaxDepositsPerEpoch;
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::MaxDepositsPerEpoch(value) = res else {
            unreachable!("request and response variants must match");
        };
        value
    }

    pub async fn get_max_withdrawals_per_epoch(&self) -> u64 {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetMaxWithdrawalsPerEpoch;
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::MaxWithdrawalsPerEpoch(value) = res else {
            unreachable!("request and response variants must match");
        };
        value
    }

    pub async fn get_minimum_validator_count(&self) -> u64 {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetMinimumValidatorCount;
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::MinimumValidatorCount(value) = res else {
            unreachable!("request and response variants must match");
        };
        value
    }

    pub async fn get_invalid_withdrawal_tax(&self) -> u64 {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetInvalidWithdrawalTax;
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::InvalidWithdrawalTax(value) = res else {
            unreachable!("request and response variants must match");
        };
        value
    }

    pub async fn get_epoch_bounds(&self, epoch: u64) -> Option<(u64, u64)> {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetEpochBounds(epoch);
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::EpochBounds(bounds) = res else {
            unreachable!("request and response variants must match");
        };
        bounds
    }

    pub async fn get_deposit(
        &self,
        index: usize,
    ) -> Option<summit_types::execution_request::DepositRequest> {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetDeposit(index);
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::Deposit(deposit) = res else {
            unreachable!("request and response variants must match");
        };
        deposit
    }

    pub async fn get_deposit_count(&self) -> usize {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetDepositCount;
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::DepositCount(count) = res else {
            unreachable!("request and response variants must match");
        };
        count
    }

    pub async fn get_withdrawal(
        &self,
        pubkey: [u8; 32],
    ) -> Option<summit_types::withdrawal::PendingWithdrawal> {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetWithdrawal(pubkey);
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::Withdrawal(withdrawal) = res else {
            unreachable!("request and response variants must match");
        };
        withdrawal
    }

    pub async fn get_state_root(&self) -> ([u8; 32], u64) {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GetStateRoot;
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::StateRoot {
            root,
            el_block_number,
        } = res
        else {
            unreachable!("request and response variants must match");
        };
        (root, el_block_number)
    }

    pub async fn generate_state_proof(
        &self,
        keys: Vec<summit_types::ssz_tree_key::SszStateKey>,
    ) -> (
        [u8; 32],
        u64,
        Vec<Option<summit_types::ssz_state_tree::StateProofEntry>>,
    ) {
        let (response, rx) = oneshot::channel();
        let request = ConsensusStateRequest::GenerateStateProof(keys, None);
        let _ = self
            .sender
            .clone()
            .send(FinalizerMessage::QueryState { request, response })
            .await;

        let res = rx
            .await
            .expect("consensus state query response sender dropped");
        let ConsensusStateResponse::StateProof {
            root,
            el_block_number,
            proofs,
        } = res
        else {
            unreachable!("request and response variants must match");
        };
        (root, el_block_number, proofs)
    }
}

impl<S: Scheme<B::Digest>, B: ConsensusBlock> Reporter for FinalizerMailbox<S, B> {
    type Activity = Update<B, S>;

    async fn report(&mut self, activity: Self::Activity) {
        self.sender
            .send(FinalizerMessage::SyncerUpdate { update: activity })
            .await
            .expect("Unable to send syncer update to Finalizer");
    }
}
