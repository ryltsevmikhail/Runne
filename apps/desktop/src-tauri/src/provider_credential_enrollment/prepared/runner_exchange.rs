use super::PreparedCredentialEnrollmentError;
use runne_api::ProviderCredentialEnrollmentActionV2 as Action;

pub(super) const fn secretless(
    action: Action,
    has_material: bool,
) -> Result<bool, PreparedCredentialEnrollmentError> {
    match (action, has_material) {
        (Action::Pair, true) => Ok(false),
        (Action::Revoke, false) => Ok(true),
        _ => Err(PreparedCredentialEnrollmentError),
    }
}

pub(super) fn finish_control_only(
    supervisor: std::sync::Arc<
        std::sync::Mutex<runne_platform_desktop::ProtectedBundledRuntimeSupervisor>,
    >,
    enrollment: runne_platform_desktop::PreparedProtectedCredentialEnrollment,
) -> Result<(), PreparedCredentialEnrollmentError> {
    let enrollment = tauri::async_runtime::block_on(
        runne_platform_desktop::ProtectedBundledRuntimeSupervisor::finish_control_only_credential_enrollment_with_rejoin(
            supervisor, enrollment,
        ),
    ).map_err(|_| PreparedCredentialEnrollmentError)?;
    (enrollment.terminal() && super::terminal_is_success(enrollment.snapshot().state()))
        .then_some(())
        .ok_or(PreparedCredentialEnrollmentError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_routes_only_pair_with_material_and_revoke_without_material() {
        for (action, material, expected) in [
            (Action::Pair, true, Some(false)),
            (Action::Pair, false, None),
            (Action::Revoke, false, Some(true)),
            (Action::Revoke, true, None),
            (Action::MigrateLegacy, false, None),
            (Action::MigrateLegacy, true, None),
        ] {
            assert_eq!(secretless(action, material).ok(), expected);
        }
    }
}
