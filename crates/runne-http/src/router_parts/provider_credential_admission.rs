/// Rejects V2 advertisement until its transport-owned admission exists.
pub(super) fn require_provider_credential_enrollment_admission(
    runtime_profile_state: &RuntimeProfileHttpState,
    mounted: bool,
) -> Result<(), SecureLocalHttpHostError> {
    let advertised =
        runtime_profile_state.advertises(runne_api::PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2);
    #[cfg(target_os = "linux")]
    let consistent = linux_dormant_mount_consistent(advertised, mounted);
    #[cfg(not(target_os = "linux"))]
    let consistent = advertised == mounted;
    if !consistent {
        return Err(SecureLocalHttpHostError::ProviderCredentialEnrollmentAdmissionMissing);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_dormant_mount_consistent(advertised: bool, mounted: bool) -> bool {
    advertised == mounted || (mounted && !advertised)
}

#[cfg(all(test, target_os = "linux"))]
mod dormant_linux_tests {
    #[test]
    fn linux_allows_only_the_unadvertised_dormant_mount() {
        assert!(super::linux_dormant_mount_consistent(false, true));
        assert!(super::linux_dormant_mount_consistent(false, false));
        assert!(super::linux_dormant_mount_consistent(true, true));
        assert!(!super::linux_dormant_mount_consistent(true, false));
    }
}
