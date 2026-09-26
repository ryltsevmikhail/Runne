use super::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl;
use crate::protected_activation::ProtectedActivationChannel;
use runne_api::{
    LaunchAuthorityError, ProtectedActivationKeys, ProtectedCredentialEnrollmentOwnedLaunchV3,
};
use runne_application::local_session::LocalSessionService;

#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    mut channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    mut owned: ProtectedCredentialEnrollmentOwnedLaunchV3,
    sessions: Arc<Mutex<LocalSessionService>>,
    session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    ticket_clock: TicketClock,
    mut enrollment: V3EnrollmentDispatch,
    root_admission: Option<Arc<crate::protected_activation::ProtectedRootControl>>,
) -> Result<(), LaunchAuthorityError> {
    let runtime = match enrollment.control.take() {
        Some(control) => {
            runtime_for_enrolled_session(&keys, &owned, &sessions, control, enrollment)?
        }
        None => runtime_without_enrollment(enrollment),
    };
    let mut runtime = runtime;
    let result = super::serve_v3_transcript(
        &mut channel,
        &keys,
        &mut owned,
        &sessions,
        &session_clock,
        &ticket_clock,
        &mut runtime,
        root_admission,
    );
    if result.is_err() {
        runtime
            .terminate_retained_writer()
            .map_err(super::runtime::map_enrollment_error)?;
    }
    result
}

fn runtime_for_enrolled_session(
    keys: &ProtectedActivationKeys,
    owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
    sessions: &Arc<Mutex<LocalSessionService>>,
    control: Arc<DaemonProviderCredentialEnrollmentControl>,
    mut enrollment: V3EnrollmentDispatch,
) -> Result<V3EnrollmentRuntime, LaunchAuthorityError> {
    let capability = enrollment
        .linux_writer_capability
        .take()
        .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
    let live = live_session::LiveEnrollmentSession::capture(sessions, owned)?;
    let rendezvous = enrollment.rendezvous.into_owned()?;
    let session = control
        .start_protected_session(keys, owned, rendezvous)
        .map_err(runtime::map_enrollment_error)?;
    Ok(V3EnrollmentRuntime {
        live: Some(live),
        session: Some(session),
        terminal: true,
        linux_writer: None,
        linux_writer_capability: Some(capability),
        round_previous: Some(owned.clone()),
        linux_control: Some(control),
    })
}

fn runtime_without_enrollment(enrollment: V3EnrollmentDispatch) -> V3EnrollmentRuntime {
    drop(enrollment);
    V3EnrollmentRuntime {
        live: None,
        session: None,
        terminal: true,
        linux_writer: None,
        linux_writer_capability: None,
        round_previous: None,
        linux_control: None,
    }
}

#[cfg(all(test, feature = "desktop-protected"))]
mod tests {
    use super::*;

    #[test]
    fn shutdown_revokes_published_http_facts_before_return() {
        let (control, keys) = crate::application::provider_credential_enrollment::test_control();
        let (owned, _, _) = crate::protected_activation::test_enrollment_owned_and_sessions();
        let session_id = *owned.session_id();
        let session = control
            .start_protected_session(
                &keys,
                &owned,
                crate::application::provider_credential_enrollment::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous::create().unwrap(),
            )
            .unwrap();
        assert!(
            crate::application::provider_credential_enrollment::test_http_status_facts_available(
                &control, session_id
            )
        );
        let mut runtime = V3EnrollmentRuntime {
            live: None,
            session: Some(session),
            terminal: true,
            linux_writer: None,
            linux_writer_capability: None,
            round_previous: Some(owned),
            linux_control: Some(control.clone()),
        };

        runtime.revoke_shutdown_authorization();

        assert!(
            !crate::application::provider_credential_enrollment::test_http_status_facts_available(
                &control, session_id
            )
        );
    }
}
