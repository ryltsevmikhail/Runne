//! Fail-closed mounting guard for credential enrollment V2.

use runne_api::PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2;

use crate::runtime_profile::RuntimeProfileHttpState;

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
