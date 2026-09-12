#[cfg(any(unix, windows))]
pub(crate) fn validate_protected_bootstrap_connection(
    config: &ConfigurationSnapshot,
    connection: &rusqlite::Connection,
    expected: &StableRuntimeBindingV1,
    pending: Option<&PendingFirstActivationV1>,
    authenticated_profile: Option<&ProtectedRuntimeProfileV1>,
) -> Result<(), LaunchAuthorityError> {
    let expected_profile = match authenticated_profile {
        Some(profile) => profile.clone(),
        None => first_activation::expected_profile(None)?,
    };
    match pending {
        Some(pending) => first_activation::validate_resume_first_activation_connection(
            config,
            connection,
            pending,
            &expected_profile,
        ),
        None => first_activation::validate_existing_connection(
            config,
            connection,
            expected,
            None,
            &expected_profile,
        ),
    }
}
