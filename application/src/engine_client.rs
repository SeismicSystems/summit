/*
This is the Client to speak with the engine API on Reth

The engine api is what consensus uses to drive the execution client forward. There is only 3 main endpoints that we hit
but they do different things depending on the args

engine_forkchoiceUpdatedV3 : This updates the forkchoice head to a specific head. If the optionally arg payload_attributes is provided it will also trigger the
    building of a new block on the execution client. This will mainly be called in 2 scenerios: 1) When a validator has been selected to propose a block he will
    call with payload_attributes to trigger the building process. 2) After a block a validator has previously validated a block(therefore saved on execution client) and
    it has received enough attestations to be committed by consensus


engine_getPayloadV3 : This is called to retrieve a block from execution client. This is called after a node has previously called engine_forkchoiceUpdatedV3 with payload
    attributes to begin the build process

engine_newPayloadV3 : This is called to store(not commit) and validate blocks received from other validators. This is called after receiving a block and it is how we decide if
    we should attest if the block is valid. If it is valid and we reach quorom when we call engine_forkchoiceUpdatedV3 it will set this block to head

*/
use alloy_eips::eip4895::Withdrawal;
use alloy_provider::{ProviderBuilder, RootProvider, ext::EngineApi};
use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV4, ForkchoiceState, PayloadAttributes, PayloadId, PayloadStatus,
};
use tracing::{error, warn};

use alloy_transport_ipc::IpcConnect;
use std::future::Future;
use summit_types::Block;

pub trait EngineClient: Clone + Send + Sync + 'static {
    fn start_building_block(
        &self,
        fork_choice_state: ForkchoiceState,
        timestamp: u64,
        withdrawals: Vec<Withdrawal>,
    ) -> impl Future<Output = Option<PayloadId>> + Send;

    fn get_payload(
        &self,
        payload_id: PayloadId,
    ) -> impl Future<Output = ExecutionPayloadEnvelopeV4> + Send;

    fn check_payload(&self, block: &Block) -> impl Future<Output = PayloadStatus> + Send;

    fn commit_hash(&self, fork_choice_state: ForkchoiceState) -> impl Future<Output = ()> + Send;
}

#[derive(Clone)]
pub struct RethEngineClient {
    provider: RootProvider,
}

impl RethEngineClient {
    pub async fn new(engine_ipc_path: String) -> Self {
        let ipc = IpcConnect::new(engine_ipc_path);
        let provider = ProviderBuilder::default().connect_ipc(ipc).await.unwrap();
        Self { provider }
    }
}

impl EngineClient for RethEngineClient {
    async fn start_building_block(
        &self,
        fork_choice_state: ForkchoiceState,
        timestamp: u64,
        withdrawals: Vec<Withdrawal>,
    ) -> Option<PayloadId> {
        let payload_attributes = PayloadAttributes {
            timestamp,
            prev_randao: [0; 32].into(),
            // todo(dalton): this should be the validators public key
            suggested_fee_recipient: [1; 20].into(),
            withdrawals: Some(withdrawals),
            // todo(dalton): we should make this something that we can associate with the simplex height
            parent_beacon_block_root: Some([1; 32].into()),
        };
        let res = self
            .provider
            .fork_choice_updated_v3(fork_choice_state, Some(payload_attributes))
            .await
            .unwrap();

        if res.is_invalid() {
            error!("invalid returned for forkchoice state {fork_choice_state:?}: {res:?}");
        }
        if res.is_syncing() {
            warn!("syncing returned for forkchoice state {fork_choice_state:?}: {res:?}");
        }

        res.payload_id
    }

    async fn get_payload(&self, payload_id: PayloadId) -> ExecutionPayloadEnvelopeV4 {
        self.provider.get_payload_v4(payload_id).await.unwrap()
    }

    async fn check_payload(&self, block: &Block) -> PayloadStatus {
        self.provider
            .new_payload_v4(
                block.payload.clone(),
                Vec::new(),
                [1; 32].into(),
                block.execution_requests.clone(),
            )
            .await
            .unwrap()
    }

    async fn commit_hash(&self, fork_choice_state: ForkchoiceState) {
        self.provider
            .fork_choice_updated_v3(fork_choice_state, None)
            .await
            .unwrap();
    }
}
