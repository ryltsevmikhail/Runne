#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use runne_api::VerifyProviderCredential;
use runne_api::{
    ApiActor, ApiPrincipalId, BeginProviderCredentialEnrollment, ProviderCredentialCommandContext,
    protected_credential_broker_evidence_binding,
};

use super::{EnrollmentBrokerFacts, ProtectedBundledRuntimeError};

pub(super) fn command_context(
    command: &BeginProviderCredentialEnrollment,
) -> Result<ProviderCredentialCommandContext, ProtectedBundledRuntimeError> {
    ProviderCredentialCommandContext::from_canonical_ids(
        command.command_identity(),
        command.idempotency_key(),
        ApiPrincipalId::new("protected-desktop-owner")
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?,
        ApiActor::new("runne-tauri-native-host")
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?,
    )
    .ok_or(ProtectedBundledRuntimeError::InvalidState)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn verification_command_context(
    command: &VerifyProviderCredential,
) -> Result<ProviderCredentialCommandContext, ProtectedBundledRuntimeError> {
    ProviderCredentialCommandContext::from_canonical_ids(
        command.command_identity(),
        command.command_identity(),
        ApiPrincipalId::new("protected-desktop-owner")
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?,
        ApiActor::new("runne-tauri-native-host")
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?,
    )
    .ok_or(ProtectedBundledRuntimeError::InvalidState)
}

pub(super) fn require_admission(
    admission: &runne_api::VerifiedProtectedCredentialEnrollmentAdmission,
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    confirmation: [u8; 32],
    facts: EnrollmentBrokerFacts,
) -> Result<(), ProtectedBundledRuntimeError> {
    let binding = owned.enrollment_binding();
    let broker = protected_credential_broker_evidence_binding(
        *binding.release_tuple_digest(),
        facts.binding(),
        facts.publication_public_key(),
    );
    let installation_matches =
        admission.installation_identity() == *binding.installation_identity_digest();
    let release_matches = admission.release_tuple_digest() == *binding.release_tuple_digest();
    let supervisor_matches =
        admission.desktop_supervisor_generation() == binding.desktop_supervisor_generation();
    let peer_matches =
        admission.authenticated_tauri_peer_binding() == *binding.desktop_peer_binding_digest();
    if !installation_matches
        || !release_matches
        || !supervisor_matches
        || !peer_matches
        || admission.native_confirmation_digest() != confirmation
        || admission.broker_process_evidence_digest() != broker
    {
        return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
    }
    Ok(())
}
