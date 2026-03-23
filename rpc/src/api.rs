use crate::types::{
    CheckpointInfoRes, CheckpointRes, DepositResponse, DepositTransactionResponse,
    EpochBoundsResponse, FinalizedHeaderRes, PendingWithdrawalResponse, PublicKeysResponse,
    StateProofResponse, StateRootResponse, ValidatorAccountResponse,
};
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;

#[rpc(server, client)]
pub trait SummitApi {
    #[method(name = "health")]
    async fn health(&self) -> RpcResult<String>;

    #[method(name = "getPublicKeys")]
    async fn get_public_keys(&self) -> RpcResult<PublicKeysResponse>;

    #[method(name = "getCheckpoint")]
    async fn get_checkpoint(&self, epoch: u64) -> RpcResult<CheckpointRes>;

    #[method(name = "getLatestCheckpoint")]
    async fn get_latest_checkpoint(&self) -> RpcResult<CheckpointRes>;

    #[method(name = "getLatestCheckpointInfo")]
    async fn get_latest_checkpoint_info(&self) -> RpcResult<CheckpointInfoRes>;

    #[method(name = "getFinalizedHeader")]
    async fn get_finalized_header(&self, epoch: u64) -> RpcResult<FinalizedHeaderRes>;

    #[method(name = "getLatestHeight")]
    async fn get_latest_height(&self) -> RpcResult<u64>;

    #[method(name = "getLatestEpoch")]
    async fn get_latest_epoch(&self) -> RpcResult<u64>;

    #[method(name = "getValidatorBalance")]
    async fn get_validator_balance(&self, public_key: String) -> RpcResult<u64>;

    #[method(name = "getValidatorAccount")]
    async fn get_validator_account(
        &self,
        public_key: String,
    ) -> RpcResult<ValidatorAccountResponse>;

    #[method(name = "getDepositSignature")]
    async fn get_deposit_signature(
        &self,
        amount: u64,
        address: String,
    ) -> RpcResult<DepositTransactionResponse>;

    #[method(name = "getMinimumStake")]
    async fn get_minimum_stake(&self) -> RpcResult<u64>;

    #[method(name = "getMaximumStake")]
    async fn get_maximum_stake(&self) -> RpcResult<u64>;

    #[method(name = "getEpochLength")]
    async fn get_epoch_length(&self) -> RpcResult<u64>;

    #[method(name = "getAllowedTimestampFuture")]
    async fn get_allowed_timestamp_future(&self) -> RpcResult<u64>;

    #[method(name = "getEpochBounds")]
    async fn get_epoch_bounds(&self, epoch: u64) -> RpcResult<EpochBoundsResponse>;

    #[method(name = "getDeposit")]
    async fn get_deposit(&self, index: usize) -> RpcResult<DepositResponse>;

    #[method(name = "getDepositCount")]
    async fn get_deposit_count(&self) -> RpcResult<usize>;

    #[method(name = "getPendingWithdrawal")]
    async fn get_pending_withdrawal(
        &self,
        public_key: String,
    ) -> RpcResult<PendingWithdrawalResponse>;
}

#[rpc(server, client)]
pub trait SummitProofApi {
    #[method(name = "getStateRoot")]
    async fn get_state_root(&self) -> RpcResult<StateRootResponse>;

    #[method(name = "getStateProof")]
    async fn get_state_proof(&self, keys: Vec<String>) -> RpcResult<StateProofResponse>;
}

#[rpc(server, client)]
pub trait SummitGenesisApi {
    #[method(name = "health")]
    async fn health(&self) -> RpcResult<String>;

    #[method(name = "getPublicKeys")]
    async fn get_public_keys(&self) -> RpcResult<PublicKeysResponse>;

    #[method(name = "sendGenesis")]
    async fn send_genesis(&self, genesis_content: String) -> RpcResult<String>;
}
