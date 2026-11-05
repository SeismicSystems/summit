//! The follower listener: the syncer's backfill resolver served over RPC.

use crate::api::SummitFollowerApiServer;
use crate::error::RpcError;
use crate::types::ResolverKey;
use alloy_primitives::Bytes;
use async_trait::async_trait;
use jsonrpsee::core::RpcResult;
use std::sync::Arc;
use summit_syncer::ingress::handler::{Handler, Key};
use summit_types::Digest;
use summit_types::consensus_state_query::ConsensusStateQuery;
use summit_types::scheme::MultisigScheme;
use tokio::sync::Semaphore;

/// Most `getResolverValue` requests the listener keeps waiting on the syncer
/// at once. Each one holds a slot in the syncer's resolver mailbox, which p2p
/// peers' backfill requests also use, so this keeps the listener to a small
/// share of it however many requests its connections carry.
pub(crate) const MAX_IN_FLIGHT: usize = 1024;

/// Serves resolver keys from this node's syncer, as the backfill resolver
/// does for p2p peers.
#[derive(Clone)]
pub struct FollowerRpcServer {
    resolver: Handler<Digest>,
    state_query: ConsensusStateQuery<MultisigScheme>,
    in_flight: Arc<Semaphore>,
}

impl FollowerRpcServer {
    pub fn new(
        resolver: Handler<Digest>,
        state_query: ConsensusStateQuery<MultisigScheme>,
    ) -> Self {
        Self {
            resolver,
            state_query,
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
        }
    }
}

#[async_trait]
impl SummitFollowerApiServer for FollowerRpcServer {
    async fn get_resolver_value(&self, key: ResolverKey) -> RpcResult<Option<Bytes>> {
        let _permit = self
            .in_flight
            .try_acquire()
            .map_err(|_| RpcError::ResolverUnavailable)?;
        let reply = self
            .resolver
            .try_produce(Key::<Digest>::from(key))
            .ok_or(RpcError::ResolverUnavailable)?;
        // The syncer drops the reply sender when it doesn't have the value.
        Ok(reply.await.ok().map(Bytes::from))
    }

    async fn get_latest_height(&self) -> RpcResult<u64> {
        Ok(self.state_query.get_latest_height().await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::Runner as _;
    use std::num::NonZeroUsize;

    #[test]
    fn caps_requests_in_flight() {
        commonware_runtime::tokio::Runner::default().start(|context| async move {
            // Room for one more request than the cap, so a rejection comes
            // from the cap, not a full mailbox.
            let (_syncer, handler) = summit_syncer::ingress::handler::init(
                context,
                NonZeroUsize::new(MAX_IN_FLIGHT + 1).unwrap(),
            );
            let (state_query, _) = ConsensusStateQuery::new(1);
            let server = FollowerRpcServer::new(handler, state_query);
            let key = ResolverKey::Finalized { height: 1 };

            // The syncer never answers, so these hold every permit.
            let mut pending = futures::future::join_all(
                (0..MAX_IN_FLIGHT).map(|_| server.get_resolver_value(key)),
            );
            assert!(futures::poll!(&mut pending).is_pending());

            match futures::poll!(server.get_resolver_value(key)) {
                std::task::Poll::Ready(Err(err)) => assert_eq!(err.code(), 3008),
                other => panic!("expected 3008 at the cap, got {other:?}"),
            }

            // Requests that give up release their permits.
            drop(pending);
            assert!(futures::poll!(server.get_resolver_value(key)).is_pending());
        });
    }
}
