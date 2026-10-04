//! Protected V2 credential enrollment routes and their fail-closed mount guard.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use runne_api::ProviderCredentialEnrollmentHostPort;
use std::sync::Arc;

mod admission;
mod handlers;
mod wire;

#[cfg(test)]
mod tests;

pub use admission::{
    ProviderCredentialEnrollmentHttpAdmission, ProviderCredentialEnrollmentHttpAdmissionResolver,
};

const MAX_BODY_BYTES: usize = 16 * 1024;

/// Shared protected V2 host state.
pub struct ProviderCredentialEnrollmentHttpState<H> {
    pub(super) host: Arc<H>,
    pub(super) resolver: Option<Arc<dyn ProviderCredentialEnrollmentHttpAdmissionResolver>>,
}

impl<H> Clone for ProviderCredentialEnrollmentHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
            resolver: self.resolver.clone(),
        }
    }
}

impl<H> ProviderCredentialEnrollmentHttpState<H> {
    /// Wraps one authoritative protected enrollment host.
    #[must_use]
    pub fn new(host: H) -> Self {
        Self {
            host: Arc::new(host),
            resolver: None,
        }
    }

    /// Installs the daemon-owned resolver without mounting these routes.
    #[must_use]
    pub fn with_admission_resolver<R>(host: H, resolver: R) -> Self
    where
        R: ProviderCredentialEnrollmentHttpAdmissionResolver + 'static,
    {
        Self {
            host: Arc::new(host),
            resolver: Some(Arc::new(resolver)),
        }
    }
}

/// Builds V2 routes that require a per-request server-derived admission.
///
/// The caller must insert a fresh [`ProviderCredentialEnrollmentHttpAdmission`]
/// after outer protected transport verification. This router alone is not an
/// authority and remains deliberately unmounted by the runtime profile guard.
pub fn provider_credential_enrollment_router<H>(
    state: ProviderCredentialEnrollmentHttpState<H>,
) -> Router
where
    H: ProviderCredentialEnrollmentHostPort + 'static,
{
    Router::new()
        .route(
            "/v2/provider-credential-enrollment",
            post(handlers::begin::<H>),
        )
        .route(
            "/v2/provider-credential-enrollment/resume",
            post(handlers::resume::<H>),
        )
        .route(
            "/v2/providers/{provider}/credential-enrollment",
            get(handlers::status::<H>),
        )
        .route(
            "/v2/provider-credential-enrollment/verify",
            post(handlers::verify::<H>),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

/// Builds the enrollment endpoints below one exact provider realm.
///
/// This router is composed only with that provider's daemon control. Shared
/// request bodies still carry the closed provider id and are checked by the
/// admission resolver; the native broker remains the only mutation path.
pub fn provider_credential_enrollment_router_for_provider<H>(
    state: ProviderCredentialEnrollmentHttpState<H>,
    provider: &'static str,
) -> Router
where
    H: ProviderCredentialEnrollmentHostPort + 'static,
{
    Router::new()
        .route(
            &format!("/v2/providers/{provider}/credential-enrollment/begin"),
            post(handlers::begin::<H>),
        )
        .route(
            &format!("/v2/providers/{provider}/credential-enrollment/resume"),
            post(handlers::resume::<H>),
        )
        .route(
            &format!("/v2/providers/{provider}/credential-enrollment"),
            get(handlers::status_scoped::<H>),
        )
        .route(
            &format!("/v2/providers/{provider}/credential-enrollment/verify"),
            post(handlers::verify::<H>),
        )
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(axum::Extension(provider))
        .with_state(state)
}
