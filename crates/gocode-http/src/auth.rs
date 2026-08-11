//! Auth middleware for bearer token authentication.
//!
//! Provides `AuthLayer` / `AuthMiddleware` tower service that validates
//! `Authorization: Bearer <hex>` headers against a provisioned daemon token.

use axum::{
    body::Body,
    http::{HeaderMap, Request, Response, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use gocode_api::ApiPrincipalId;
use gocode_api::RuntimeSessionBinding;
use gocode_application::local_session::LocalSessionService;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;
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

/// Builds a redacted local-session authorization header.
pub fn session_authorization_header(
    authority: &str,
) -> Result<axum::http::HeaderValue, RuntimeApiError> {
    let wire_value = format!("GocodeSession {authority}");
    let mut header = axum::http::HeaderValue::from_str(&wire_value)
        .map_err(|_| RuntimeApiError::invalid_request())?;
    header.set_sensitive(true);
    Ok(header)
}

/// Redacted invalid-request marker returned only by the header builder.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeApiError;
impl RuntimeApiError {
    fn invalid_request() -> Self {
        Self
    }
}

/// Session middleware validating exactly one base64url-no-pad authority.
#[derive(Clone)]
pub struct SessionAuthLayer {
    service: Arc<Mutex<LocalSessionService>>,
    binding: Option<RuntimeSessionBinding>,
    clock: Arc<dyn Fn() -> Duration + Send + Sync>,
}
impl SessionAuthLayer {
    /// Creates a composable layer over the real bounded authority service.
    pub fn new(
        service: Arc<Mutex<LocalSessionService>>,
        binding: RuntimeSessionBinding,
        clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    ) -> Self {
        Self {
            service,
            binding: Some(binding),
            clock,
        }
    }

    /// Creates a layer that follows protected in-process session rotation.
    pub fn new_dynamic(
        service: Arc<Mutex<LocalSessionService>>,
        clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    ) -> Self {
        Self {
            service,
            binding: None,
            clock,
        }
    }
}
impl<S> tower::Layer<S> for SessionAuthLayer {
    type Service = SessionAuthMiddleware<S>;
    fn layer(&self, inner: S) -> Self::Service {
        SessionAuthMiddleware {
            inner,
            service: self.service.clone(),
            binding: self.binding.clone(),
            clock: self.clock.clone(),
        }
    }
}
#[derive(Clone)]
pub struct SessionAuthMiddleware<S> {
    inner: S,
    service: Arc<Mutex<LocalSessionService>>,
    binding: Option<RuntimeSessionBinding>,
    clock: Arc<dyn Fn() -> Duration + Send + Sync>,
}
impl<S> tower::Service<Request<Body>> for SessionAuthMiddleware<S>
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
        let inbound_authorization: Vec<_> = req
            .headers()
            .get_all("authorization")
            .iter()
            .cloned()
            .collect();
        req.headers_mut().remove("authorization");
        for mut value in inbound_authorization {
            value.set_sensitive(true);
            req.headers_mut().append("authorization", value);
        }
        let authenticated = extract_session_authority(req.headers()).and_then(|authority| {
            self.service
                .lock()
                .ok()
                .and_then(|mut service| match self.binding.as_ref() {
                    Some(binding) => service
                        .authorize_wire_for_binding(&authority, binding, (self.clock)())
                        .ok(),
                    None => service.authorize_wire(&authority, (self.clock)()).ok(),
                })
        });
        if let Some(authenticated) = authenticated {
            let principal =
                AuthenticatedPrincipal(authenticated.binding.stable().principal_id().clone());
            req.extensions_mut().insert(authenticated);
            req.extensions_mut().insert(principal);
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
fn extract_session_authority(headers: &HeaderMap) -> Option<[u8; 32]> {
    let mut values = headers.get_all("authorization").iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    if scheme != "GocodeSession"
        || token.is_empty()
        || token.contains('=')
        || token.contains(char::is_whitespace)
    {
        return None;
    }
    URL_SAFE_NO_PAD.decode(token).ok()?.try_into().ok()
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
