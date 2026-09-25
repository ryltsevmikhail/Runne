use std::sync::Arc;
#[cfg(target_os = "macos")]
mod completion;
#[cfg(all(test, target_os = "macos"))]
pub(in crate::protected_activation) use completion::with_control;
#[cfg(target_os = "macos")]
mod writer_driver;
#[cfg(unix)]
include!("runtime/shutdown.rs");
#[cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
#[path = "runtime_state.rs"]
pub(super) mod runtime_state;
pub(super) use runtime_state::V3EnrollmentRuntime;
#[cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
pub(super) fn map_enrollment_error(
    error: runne_api::ProviderCredentialEnrollmentHostError,
) -> runne_api::LaunchAuthorityError {
    match error {
        runne_api::ProviderCredentialEnrollmentHostError::Unsupported => {
            runne_api::LaunchAuthorityError::UnsupportedPlatformBackend
        }
        runne_api::ProviderCredentialEnrollmentHostError::Unavailable => {
            runne_api::LaunchAuthorityError::ProtectedChannelUnavailable
        }
        _ => runne_api::LaunchAuthorityError::OwnershipMismatch,
    }
}

#[cfg(unix)]
pub(super) fn unix_now_millis() -> Result<u64, runne_api::LaunchAuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(runne_api::LaunchAuthorityError::StaleLaunchAuthority)
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(super) fn bind_broker(
    keys: &runne_api::ProtectedActivationKeys,
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    session: &mut crate::application::provider_credential_enrollment::DaemonProtectedCredentialEnrollmentSession,
) -> Result<
    Option<crate::protected_activation::broker_handoff::BrokerHandoffDispatch>,
    runne_api::LaunchAuthorityError,
> {
    if session.begun_is_terminal() {
        return Ok(None);
    }
    let handoff = session
        .take_bound_broker_handoff()
        .map_err(map_enrollment_error)?;
    crate::protected_activation::broker_handoff::BrokerHandoffDispatch::from_bound_enrollment(
        keys, owned, handoff,
    )
    .map(Some)
}

pub(crate) const fn enrollment_transcript_allows_rotation(
    has_session: bool,
    terminal: bool,
) -> bool {
    !has_session || terminal
}

impl V3EnrollmentRuntime {
    /// Off macOS there is no credential enrollment session in the V3 loop.
    pub(super) const fn has_session(&self) -> bool {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        {
            self.session.is_some()
        }
        #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
        {
            false
        }
    }
}

#[cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    expect(
        dead_code,
        reason = "the shutdown gate is consumed by the macOS protected session; Linux composition lands later"
    )
)]
pub(crate) fn require_shutdown_terminal(
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))] session: Option<&()>,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    session: Option<&crate::application::provider_credential_enrollment::DaemonProtectedCredentialEnrollmentSession>,
    terminal: bool,
) -> Result<(), runne_api::LaunchAuthorityError> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        if session.is_some() && !terminal {
            return Err(runne_api::LaunchAuthorityError::OwnershipMismatch);
        }
        if let Some(session) = session {
            session
                .require_durable_terminal()
                .map_err(map_enrollment_error)?;
        }
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (session, terminal);
    }
    Ok(())
}

#[cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
fn acquire_after_preflight<P, A, E>(
    preflight: impl FnOnce() -> Result<P, E>,
    acquire: impl FnOnce() -> A,
) -> Result<(P, A), E> {
    let prepared = preflight()?;
    Ok((prepared, acquire()))
}

#[cfg(test)]
#[path = "runtime_cfg_scope_tests.rs"]
mod cfg_scope_tests;
#[cfg(test)]
mod tests {
    use std::cell::Cell;

    #[test]
    fn failed_channel_preflight_does_not_take_writer_authority() {
        let acquired = Cell::new(false);
        let result = super::acquire_after_preflight(
            || Err::<(), _>("daemon-start-unavailable"),
            || acquired.set(true),
        );
        assert_eq!(result, Err("daemon-start-unavailable"));
        assert!(!acquired.get());
    }
}
