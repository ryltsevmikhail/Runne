/// Rejects V2 advertisement until its transport-owned admission exists.
pub(super) fn require_provider_credential_enrollment_admission(
    runtime_profile_state: &RuntimeProfileHttpState,
) -> Result<(), SecureLocalHttpHostError> {
    crate::provider_credential_enrollment::require_authenticated_admission(runtime_profile_state)
        .map_err(|_| SecureLocalHttpHostError::ProviderCredentialEnrollmentAdmissionMissing)
}
