struct ProtectedBootstrap<'a> {
    launch_authority_id: [u8; 16],
    bootstrap_secret: [u8; 32],
    expected_stable: &'a StableRuntimeBindingV1,
    pending_first_activation: Option<&'a PendingFirstActivationV1>,
    expected_profile: Option<&'a ProtectedRuntimeProfileV1>,
    freshness_check: &'a mut dyn FnMut() -> Result<(), DaemonError>,
}

/// Bootstraps one protected bundled launch without publishing a credential profile.
pub fn bootstrap_protected<F>(
    config: &ConfigurationSnapshot,
    launch_authority_id: [u8; 16],
    bootstrap_secret: [u8; 32],
    expected_stable: &StableRuntimeBindingV1,
    pending_first_activation: Option<&PendingFirstActivationV1>,
    freshness_check: F,
) -> Result<BootstrapOutcome, DaemonError>
where
    F: FnMut() -> Result<(), DaemonError>,
{
    bootstrap_protected_with_profile(
        config,
        launch_authority_id,
        bootstrap_secret,
        expected_stable,
        pending_first_activation,
        None,
        freshness_check,
    )
}

pub(crate) fn bootstrap_protected_with_profile<F>(
    config: &ConfigurationSnapshot,
    launch_authority_id: [u8; 16],
    bootstrap_secret: [u8; 32],
    expected_stable: &StableRuntimeBindingV1,
    pending_first_activation: Option<&PendingFirstActivationV1>,
    expected_profile: Option<&ProtectedRuntimeProfileV1>,
    mut freshness_check: F,
) -> Result<BootstrapOutcome, DaemonError>
where
    F: FnMut() -> Result<(), DaemonError>,
{
    if validate_uuid_v7_bytes(&launch_authority_id).is_err() || bootstrap_secret == [0; 32] {
        return Err(DaemonError::Bootstrap(
            "invalid protected launch authority".into(),
        ));
    }
    bootstrap_inner(
        config,
        Some(ProtectedBootstrap {
            launch_authority_id,
            bootstrap_secret,
            expected_stable,
            pending_first_activation,
            expected_profile,
            freshness_check: &mut freshness_check,
        }),
    )
}
