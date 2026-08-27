#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Task 15 mounts V2 only after qualified authenticated admission is composed"
    )
)]

//! Protected V2 credential enrollment routes and their fail-closed mount guard.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use runne_api::{
    PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2, ProviderCredentialEnrollmentHostPort,
};
use std::sync::Arc;

use crate::runtime_profile::RuntimeProfileHttpState;

mod admission;
mod handlers;
mod wire;

#[cfg(test)]
mod tests;

pub use admission::ProviderCredentialEnrollmentHttpAdmission;

const MAX_BODY_BYTES: usize = 16 * 1024;

/// Shared protected V2 host state.
pub struct ProviderCredentialEnrollmentHttpState<H> {
    pub(super) host: Arc<H>,
}

impl<H> Clone for ProviderCredentialEnrollmentHttpState<H> {
    fn clone(&self) -> Self {
        Self {
            host: Arc::clone(&self.host),
        }
    }
}

impl<H> ProviderCredentialEnrollmentHttpState<H> {
    /// Wraps one authoritative protected enrollment host.
    #[must_use]
    pub fn new(host: H) -> Self {
        Self {
            host: Arc::new(host),
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

/// Signals that V2 was advertised before an authenticated transport admission
/// was supplied by its owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProviderCredentialEnrollmentV2Mount {
    MissingAuthenticatedAdmission,
}

/// Rejects V2 capability advertisement until the protected transport owner
/// provides the server-derived admission required to mount its routes.
pub(crate) fn require_authenticated_admission(
    runtime_profile_state: &RuntimeProfileHttpState,
) -> Result<(), ProviderCredentialEnrollmentV2Mount> {
    if runtime_profile_state.advertises(PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2) {
        Err(ProviderCredentialEnrollmentV2Mount::MissingAuthenticatedAdmission)
    } else {
        Ok(())
    }
}
