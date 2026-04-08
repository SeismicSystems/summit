// -- Bearer token extension (set by HTTP middleware, read by RPC middleware) --

/// Marker inserted into request extensions by HTTP middleware when a valid
/// `Authorization: Bearer <token>` header is present.
#[derive(Clone, Debug)]
pub struct BearerToken(pub String);

/// Tower layer that extracts `Authorization: Bearer <token>` from HTTP
/// request headers and inserts a [`BearerToken`] into request extensions.
#[derive(Clone)]
pub struct BearerTokenLayer;

impl<S> tower::Layer<S> for BearerTokenLayer {
    type Service = BearerTokenService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        BearerTokenService { inner }
    }
}

#[derive(Clone)]
pub struct BearerTokenService<S> {
    inner: S,
}

impl<S, B> tower::Service<http::Request<B>> for BearerTokenService<S>
where
    S: tower::Service<http::Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<B>) -> Self::Future {
        let token = req
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|t| t.to_string());

        if let Some(token) = token {
            req.extensions_mut().insert(BearerToken(token));
        }
        self.inner.call(req)
    }
}
