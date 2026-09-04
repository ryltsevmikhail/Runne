use super::{live_session::LiveEnrollmentSession, runtime};
use crate::application::provider_credential_enrollment::{
    DaemonProtectedCredentialEnrollmentSession, InitialCredentialExchange,
};
use crate::protected_activation::ProtectedActivationChannel;
use runne_api::LaunchAuthorityError;
use runne_application::local_session::LocalSessionService;
use std::sync::Mutex;

/// Selects an authenticated initial transcript. No recovery-to-intent fallback.
/// Channel I/O never holds the session lock.
pub(super) fn run(
    channel: &mut ProtectedActivationChannel,
    enrollment: &mut DaemonProtectedCredentialEnrollmentSession,
    live: &LiveEnrollmentSession,
    sessions: &Mutex<LocalSessionService>,
) -> Result<(), LaunchAuthorityError> {
    let request = channel.read_control_frame()?;
    let now = runtime::unix_now_millis()?;
    let (kind, admission) = live.with_current(sessions, || {
        enrollment
            .accept_initial_request(&request, now)
            .map_err(runtime::map_enrollment_error)
    })?;
    channel.write_control_frame(&admission)?;
    let begin = channel.read_control_frame()?;
    if kind == InitialCredentialExchange::Recovery {
        return live.with_current(sessions, || {
            enrollment
                .accept_cleanup_recovery(&begin, runtime::unix_now_millis()? / 1000)
                .map_err(runtime::map_enrollment_error)
        });
    }
    let snapshot = live.with_current(sessions, || {
        enrollment
            .begin(&begin, runtime::unix_now_millis()?)
            .map_err(runtime::map_enrollment_error)
    })?;
    channel.write_control_frame(&snapshot)
}
