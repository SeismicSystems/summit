use alloy_rpc_types_engine::{ExecutionPayloadEnvelopeV4, ForkchoiceState, PayloadId, PayloadStatus};
use summit_application::engine_client::EngineClient;
use summit_types::Block;

#[derive(Clone)]
pub struct MockEngineClient {

}

impl EngineClient for MockEngineClient {

    async fn start_building_block(
        &self,
        fork_choice_state: ForkchoiceState,
        timestamp: u64,
    ) -> Option<PayloadId> {
        //let payload_attributes = PayloadAttributes {
        //    timestamp,
        //    prev_randao: [0; 32].into(),
        //    // todo(dalton): this should be the validators public key
        //    suggested_fee_recipient: [1; 20].into(),
        //    withdrawals: Some(Vec::new()),
        //    // todo(dalton): we should make this something that we can associate with the simplex height
        //    parent_beacon_block_root: Some([1; 32].into()),
        //};
        //let res = self
        //    .provider
        //    .fork_choice_updated_v3(fork_choice_state, Some(payload_attributes))
        //    .await
        //    .unwrap();

        //res.payload_id
        todo!()
    }

    async fn get_payload(&self, payload_id: PayloadId) -> ExecutionPayloadEnvelopeV4 {
        //self.provider.get_payload_v4(payload_id).await.unwrap()
        todo!()
    }

    async fn check_payload(&self, block: &Block) -> PayloadStatus {
        //self.provider
        //    .new_payload_v4(
        //        block.payload.clone(),
        //        Vec::new(),
        //        [1; 32].into(),
        //        block.execution_requests.clone(),
        //    )
        //    .await
        //    .unwrap()
        todo!()
    }

    async fn commit_hash(&self, fork_choice_state: ForkchoiceState) {
        //self.provider
        //    .fork_choice_updated_v3(fork_choice_state, None)
        //    .await
        //    .unwrap()s
        todo!();
    }
}