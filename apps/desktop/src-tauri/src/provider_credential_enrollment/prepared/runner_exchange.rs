use super::{
    CredentialIntentAction as Action, PreparedCredentialEnrollmentError,
    PreparedCredentialEnrollmentExchange, ProtectedWriterCleanup, RetainedWriterCleanup,
};
use runne_api::ProviderCredentialEnrollmentActionV2;

pub(super) const fn api_action(
    action: Action,
) -> Result<ProviderCredentialEnrollmentActionV2, PreparedCredentialEnrollmentError> {
    match action {
        Action::Pair => Ok(ProviderCredentialEnrollmentActionV2::Pair),
        Action::Revoke => Ok(ProviderCredentialEnrollmentActionV2::Revoke),
        Action::MigrateLegacy | Action::Verify => Err(PreparedCredentialEnrollmentError),
    }
}

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

/// Delivers the retained secret over the authenticated relay and completes the
/// protected enrollment transcript.
pub(super) fn finish_pair_exchange(
    exchange: &mut PreparedCredentialEnrollmentExchange,
    supervisor: &std::sync::Arc<
        std::sync::Mutex<runne_platform_desktop::ProtectedBundledRuntimeSupervisor>,
    >,
    enrollment: runne_platform_desktop::PreparedProtectedCredentialEnrollment,
    handoff: &mut RetainedWriterCleanup<ProtectedWriterCleanup>,
    secretless: bool,
) -> Result<(), PreparedCredentialEnrollmentError> {
    if secretless {
        return finish_control_only(std::sync::Arc::clone(supervisor), enrollment);
    }
    let mut enrollment = tauri::async_runtime::block_on(
        runne_platform_desktop::ProtectedBundledRuntimeSupervisor::receive_credential_secret_relay_with_rejoin(
            std::sync::Arc::clone(supervisor),
            enrollment,
        ),
    )
    .map_err(|_| PreparedCredentialEnrollmentError)?;
    let relay = enrollment
        .take_relay()
        .ok_or(PreparedCredentialEnrollmentError)?;
    let material = exchange
        .material
        .take()
        .ok_or(PreparedCredentialEnrollmentError)?;
    let native_oauth = matches!(
        material.kind(),
        runne_platform_desktop::SecureCredentialMaterialKind::NativeOAuth
    );
    let secret = material.into_pipe_bytes().into_zeroizing();
    let secret_relay = handoff
        .cleanup_mut()
        .ok_or(PreparedCredentialEnrollmentError)?
        .handoff
        .take_pair_secret_relay()
        .ok_or(PreparedCredentialEnrollmentError)?;
    if native_oauth {
        secret_relay
            .seal_and_write_native_oauth(&relay, secret)
            .map_err(|_| PreparedCredentialEnrollmentError)?;
    } else {
        secret_relay
            .seal_and_write(&relay, secret)
            .map_err(|_| PreparedCredentialEnrollmentError)?;
    }
    let enrollment = tauri::async_runtime::block_on(
        runne_platform_desktop::ProtectedBundledRuntimeSupervisor::finish_protected_credential_enrollment_with_rejoin(
            std::sync::Arc::clone(supervisor),
            enrollment,
            &relay,
        ),
    )
    .map_err(|_| PreparedCredentialEnrollmentError)?;
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
