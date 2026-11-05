//! Remote sources a follower fetches from.

use bytes::Bytes;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use std::future::Future;
use summit_rpc::SummitFollowerApiClient;
use summit_syncer::ingress::handler::Key;
use summit_syncer::resolver::opaque::Source;
use summit_types::Digest;
use tracing::debug;

/// A [`Source`] that can also report how far its chain goes.
pub trait FollowSource: Source<Digest> {
    /// The source's latest finalized height, or `None` if it can't be reached.
    /// Untrusted like everything else a source says: a follower only uses it
    /// to decide which heights to request.
    fn latest_height(&self) -> impl Future<Output = Option<u64>> + Send;
}

/// A summit node's follower listener (`--follower-rpc-port`), through
/// `getResolverValue` and `getLatestHeight`.
#[derive(Clone)]
pub struct RpcSource {
    url: String,
    client: HttpClient,
}

impl RpcSource {
    /// `max_response_size` must fit a whole block, hex encoded: see
    /// [`summit_rpc::follower_rpc_max_response_bytes`].
    pub fn new(url: &str, max_response_size: u32) -> anyhow::Result<Self> {
        let client = HttpClientBuilder::default()
            .max_response_size(max_response_size)
            .build(url)?;
        Ok(Self {
            url: url.to_string(),
            client,
        })
    }
}

impl Source<Digest> for RpcSource {
    async fn get(&self, key: Key<Digest>) -> Option<Bytes> {
        match self.client.get_resolver_value(key.into()).await {
            Ok(value) => value.map(|value| value.0),
            Err(e) => {
                debug!(url = self.url, %e, "getResolverValue failed");
                None
            }
        }
    }
}

impl FollowSource for RpcSource {
    async fn latest_height(&self) -> Option<u64> {
        self.client
            .get_latest_height()
            .await
            .inspect_err(|e| debug!(url = self.url, %e, "getLatestHeight failed"))
            .ok()
    }
}
