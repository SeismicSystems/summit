use crate::types::{
    CheckpointInfoRes, CheckpointRes, DepositTransactionResponse, PublicKeysResponse,
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

    #[method(name = "getLatestHeight")]
    async fn get_latest_height(&self) -> RpcResult<u64>;

    #[method(name = "getLatestEpoch")]
    async fn get_latest_epoch(&self) -> RpcResult<u64>;

    #[method(name = "getValidatorBalance")]
    async fn get_validator_balance(&self, public_key: String) -> RpcResult<u64>;

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
