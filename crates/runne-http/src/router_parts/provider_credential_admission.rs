/// Rejects V2 advertisement until its transport-owned admission exists.
pub(super) fn require_provider_credential_enrollment_admission(
    runtime_profile_state: &RuntimeProfileHttpState,
    mounted: bool,
) -> Result<(), SecureLocalHttpHostError> {
    if runtime_profile_state.advertises(runne_api::PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2)
        && !mounted
    {
        return Err(SecureLocalHttpHostError::ProviderCredentialEnrollmentAdmissionMissing);
    }
    Ok(())
}
