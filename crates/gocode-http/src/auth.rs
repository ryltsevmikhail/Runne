//! Auth middleware for bearer token authentication.
//!
//! Provides `AuthLayer` / `AuthMiddleware` tower service that validates
//! `Authorization: Bearer <hex>` headers against a provisioned daemon token.

use axum::{
    body::Body,
    http::{HeaderMap, Request, Response, StatusCode},
};
use gocode_api::ApiPrincipalId;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use subtle::ConstantTimeEq;

use crate::error::{RequestId, canonical_error_response};

/// Closed authenticated identity inserted into request extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal(ApiPrincipalId);

impl AuthenticatedPrincipal {
    /// Returns the validated API principal.
    pub fn as_api_principal(&self) -> &ApiPrincipalId {
        &self.0
    }
}

// ── Public helpers ────────────────────────────────────────────────────

/// Extract a Bearer token from request headers.
///
/// Parses the `Authorization` header, expecting `Bearer <hex>` format.
/// Returns the decoded bytes on success, or `None` if the header is
/// missing, has the wrong scheme, or contains non-hex data.
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<Vec<u8>> {
    let mut values = headers.get_all("Authorization").iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value_str = value.to_str().ok()?;
    let (scheme, token) = value_str.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    if token.len() != 64 {
        return None;
    }
    hex::decode(token).ok()
}

// ── AuthLayer ─────────────────────────────────────────────────────────

/// Tower layer that adds bearer token authentication.
///
/// Wraps an inner service and rejects requests that don't present a
/// valid `Authorization: Bearer <hex>` header whose decoded value
/// matches the configured 32-byte token.
#[derive(Clone)]
pub struct AuthLayer {
    token: [u8; 32],
    principal: ApiPrincipalId,
}

impl AuthLayer {
    /// Create a new auth layer with the given expected token.
    pub fn new(token: [u8; 32]) -> Self {
        Self {
            token,
            principal: ApiPrincipalId::new("local-owner")
                .expect("the built-in local principal is valid"),
        }
    }

    /// Creates an auth layer with an explicitly configured local principal.
    pub fn with_principal(token: [u8; 32], principal: ApiPrincipalId) -> Self {
        Self { token, principal }
    }
}

impl<S> tower::Layer<S> for AuthLayer {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> AuthMiddleware<S> {
        AuthMiddleware {
            inner,
            token: self.token,
            principal: self.principal.clone(),
        }
    }
}

// ── AuthMiddleware ────────────────────────────────────────────────────

/// Tower middleware that validates bearer tokens.
///
/// If the request contains a valid `Authorization: Bearer <hex>` header
/// whose hex-decoded value matches the configured token (constant-time
/// comparison), the request is forwarded to the inner service.
/// Otherwise, a `401 Unauthorized` response is returned.
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    token: [u8; 32],
    principal: ApiPrincipalId,
}

impl<S> tower::Service<Request<Body>> for AuthMiddleware<S>
where
    S: tower::Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let authorized = extract_bearer_token(req.headers())
            .map(|received| {
                if received.len() == 32 {
                    bool::from(received.ct_eq(&self.token))
                } else {
                    false
                }
            })
            .unwrap_or(false);

        if authorized {
            req.extensions_mut()
                .insert(AuthenticatedPrincipal(self.principal.clone()));
            let mut inner = self.inner.clone();
            Box::pin(async move { inner.call(req).await })
        } else {
            let request_id = req
                .extensions()
                .get::<RequestId>()
                .cloned()
                .unwrap_or_else(RequestId::generate);
            let response =
                canonical_error_response(StatusCode::UNAUTHORIZED, "unauthorized", &request_id);
            Box::pin(async move { Ok(response) })
        }
    }
}
