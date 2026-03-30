use jsonrpsee::server::middleware::rpc::{Batch, Notification, Request, RpcServiceT};
use jsonrpsee::types::{ErrorObject, Extensions};
use jsonrpsee_core::server::MethodResponse;
use std::sync::Arc;

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

// -- RPC middleware that gates admin methods behind bearer token auth --

const ADMIN_METHODS: &[&str] = &["pause", "unpause"];

#[derive(Clone)]
pub struct AdminAuthLayer {
    admin_token: Arc<String>,
}

impl AdminAuthLayer {
    pub fn new(admin_token: String) -> Self {
        Self {
            admin_token: Arc::new(admin_token),
        }
    }
}

impl<S> tower::Layer<S> for AdminAuthLayer {
    type Service = AdminAuthService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        AdminAuthService {
            inner,
            admin_token: self.admin_token.clone(),
        }
    }
}

#[derive(Clone)]
pub struct AdminAuthService<S> {
    inner: S,
    admin_token: Arc<String>,
}

fn check_auth(extensions: &Extensions, expected: &str) -> bool {
    extensions
        .get::<BearerToken>()
        .map(|t| t.0 == expected)
        .unwrap_or(false)
}

impl<S> RpcServiceT for AdminAuthService<S>
where
    S: RpcServiceT<
            MethodResponse = MethodResponse,
            BatchResponse = MethodResponse,
            NotificationResponse = MethodResponse,
        > + Clone
        + Send
        + Sync
        + 'static,
{
    type MethodResponse = MethodResponse;
    type NotificationResponse = MethodResponse;
    type BatchResponse = MethodResponse;

    fn call<'a>(
        &self,
        req: Request<'a>,
    ) -> impl std::future::Future<Output = Self::MethodResponse> + Send + 'a {
        let is_admin = ADMIN_METHODS.contains(&req.method_name());
        let authorized = !is_admin || check_auth(req.extensions(), &self.admin_token);
        let service = self.inner.clone();

        async move {
            if !authorized {
                return MethodResponse::error(
                    req.id,
                    ErrorObject::owned(-32001, "Unauthorized: valid admin token required", None::<()>),
                );
            }
            service.call(req).await
        }
    }

    fn batch<'a>(
        &self,
        batch: Batch<'a>,
    ) -> impl std::future::Future<Output = Self::BatchResponse> + Send + 'a {
        self.inner.batch(batch)
    }

    fn notification<'a>(
        &self,
        notif: Notification<'a>,
    ) -> impl std::future::Future<Output = Self::NotificationResponse> + Send + 'a {
        self.inner.notification(notif)
    }
}
