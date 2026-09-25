use super::*;
mod clocks;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod discovery;
#[cfg(unix)]
pub(crate) mod initial_exchange;
mod live_session;
pub(crate) mod qualification_admission;
mod renewal;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod round;
#[cfg(unix)]
mod runtime;
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
use clocks::QualificationClock;
use clocks::TicketClock;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) use clocks::macos_continuous_ticket_clock;
#[cfg(all(unix, not(all(target_os = "macos", target_arch = "aarch64"))))]
pub(crate) use clocks::unix_wall_ticket_clock;
#[cfg(unix)]
use runtime::V3EnrollmentRuntime;
#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
pub(crate) use runtime::require_shutdown_terminal;
#[cfg(all(test, target_os = "macos"))]
pub(super) use runtime::with_control;
#[cfg(unix)]
pub(super) use runtime::{V3EnrollmentDispatch, enrollment_transcript_allows_rotation};
/// Serves enrollment V3 renewal, broker writer-handoff, and shutdown frames.
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "standalone V3 entry awaits a launch-path consumer"
    )
)]
#[cfg_attr(not(unix), allow(dead_code))]
// Windows keeps the serving path compiled; the enrollment flow that starts
// it is typed-Unsupported here.
pub(crate) fn run_control_loop_v3(
    channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    owned_launch: ProtectedCredentialEnrollmentOwnedLaunchV3,
    local_session_service: Arc<Mutex<LocalSessionService>>,
    session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    ticket_clock: TicketClock,
    #[cfg(unix)] rendezvous: super::enrollment_control_transition::DaemonEnrollmentRendezvous,
) -> Result<(), LaunchAuthorityError> {
    channel.enter_control_loop()?;
    run_control_loop_v3_entered(
        channel,
        keys,
        owned_launch,
        local_session_service,
        session_clock,
        ticket_clock,
        #[cfg(unix)]
        V3EnrollmentDispatch::new(
            None,
            rendezvous,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            None,
        ),
        None,
    )
}
/// Continues entered V3; failures retain kill authority and reject V1/V2 frames.
#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
#[cfg_attr(not(unix), allow(dead_code))]
#[allow(
    clippy::too_many_arguments,
    reason = "the V3 loop consumes the exact per-platform launch inputs; grouping the cfg-gated tail would blur platform boundaries"
)]
pub(crate) fn run_control_loop_v3_entered(
    mut channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    mut owned_launch: ProtectedCredentialEnrollmentOwnedLaunchV3,
    local_session_service: Arc<Mutex<LocalSessionService>>,
    session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    ticket_clock: TicketClock,
    #[cfg(unix)] mut enrollment: V3EnrollmentDispatch,
    #[cfg(all(unix, feature = "desktop-protected"))] root_admission: Option<
        Arc<crate::protected_activation::ProtectedRootControl>,
    >,
) -> Result<(), LaunchAuthorityError> {
    #[cfg(unix)]
    let mut runtime = match enrollment.control.take() {
        #[cfg(unix)]
        Some(control) => {
            #[cfg(target_os = "linux")]
            let linux_writer_capability = enrollment.linux_writer_capability.take();
            let live = live_session::LiveEnrollmentSession::capture(
                &local_session_service,
                &owned_launch,
            )?;
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let round = enrollment
                .round_profile
                .take()
                .map(|profile| round::RoundContext {
                    profile,
                    control: Arc::clone(&control),
                    previous: owned_launch.clone(),
                });
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let installed_facts = enrollment
                .installed_facts
                .take()
                .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let credential_service_configuration =
                installed_facts.runtime_credential_service_configuration();
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let credential_service_session =
                super::credential_service_registration::receive_required_registration(
                    &mut channel,
                    &keys,
                    &owned_launch,
                    &installed_facts,
                    runtime::unix_now_millis()?,
                )?;
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let credential_service = credential_service_session
                .map(|session| control.install_credential_service_session(session))
                .transpose()
                .map_err(runtime::map_enrollment_error)?;
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let (initial_request, qualification) = initial_exchange::read_admitted_initial_request(
                &mut channel,
                &keys,
                &owned_launch,
                &installed_facts,
                &mut enrollment,
            )?;
            #[cfg(not(target_os = "macos"))]
            let initial_request = channel.read_control_frame()?;
            let owned_rendezvous = enrollment.rendezvous.into_owned()?;
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let mut enrollment = control
                .start_protected_session(&keys, &owned_launch, owned_rendezvous, installed_facts)
                .map_err(runtime::map_enrollment_error)?;
            #[cfg(target_os = "linux")]
            let mut enrollment = control
                .start_protected_session(&keys, &owned_launch, owned_rendezvous)
                .map_err(runtime::map_enrollment_error)?;
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            if let Some(qualification) = qualification {
                enrollment = enrollment
                    .retain_qualification(qualification)
                    .map_err(runtime::map_enrollment_error)?;
            }
            initial_exchange::run(
                &mut channel,
                &mut enrollment,
                &live,
                &local_session_service,
                initial_request,
            )?;
            let terminal = enrollment.begun_is_terminal();
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            let broker = runtime::bind_broker(&keys, &owned_launch, &mut enrollment)?;
            #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
            let linux_writer = if terminal {
                None
            } else {
                let capability =
                    linux_writer_capability.ok_or(LaunchAuthorityError::OwnershipMismatch)?;
                Some(runtime::launch_after_begin(
                    &mut enrollment,
                    capability,
                    channel.unix_stream(),
                    &keys,
                )?)
            };
            #[cfg(all(target_os = "linux", not(feature = "desktop-protected")))]
            let linux_writer = {
                let _ = linux_writer_capability;
                None
            };
            V3EnrollmentRuntime {
                #[cfg(target_os = "macos")]
                deferred_control: None,
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                round,
                live: Some(live),
                #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
                broker,
                session: Some(enrollment),
                terminal,
                #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
                linux_writer,
                #[cfg(target_os = "macos")]
                claim_measurements: None,
                #[cfg(target_os = "macos")]
                channel: None,
                #[cfg(target_os = "macos")]
                credential_service,
                #[cfg(target_os = "macos")]
                credential_service_configuration,
            }
        }
        None => V3EnrollmentRuntime {
            #[cfg(target_os = "macos")]
            deferred_control: None,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            round: None,
            live: None,
            // Off macOS there is no credential writer yet: the broker dispatch
            // stays unmounted and the V3 transcript serves renewal, discovery,
            // and shutdown only.
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            broker: Some(super::broker_handoff::BrokerHandoffDispatch::new(
                &keys,
                &owned_launch,
                enrollment.rendezvous,
            )?),
            #[cfg(any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64")))]
            session: None,
            terminal: true,
            #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
            linux_writer: None,
            #[cfg(target_os = "macos")]
            claim_measurements: None,
            #[cfg(target_os = "macos")]
            channel: None,
            #[cfg(target_os = "macos")]
            credential_service: None,
            #[cfg(target_os = "macos")]
            credential_service_configuration: None,
        },
    };
    #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
    if let Some(writer) = runtime.linux_writer.as_mut() {
        let result = writer.drive_claimed_writer(
            &mut channel,
            &local_session_service,
            &keys,
            runtime
                .session
                .as_mut()
                .ok_or(LaunchAuthorityError::OwnershipMismatch)?,
            runtime
                .live
                .as_ref()
                .ok_or(LaunchAuthorityError::OwnershipMismatch)?,
        );
        if let Err(error) = result {
            runtime
                .terminate_retained_writer()
                .map_err(runtime::map_enrollment_error)?;
            return Err(error);
        }
        runtime.terminal = true;
    }
    let transcript = serve_v3_transcript(
        &mut channel,
        &keys,
        &mut owned_launch,
        &local_session_service,
        &session_clock,
        &ticket_clock,
        #[cfg(unix)]
        &mut runtime,
        #[cfg(all(unix, feature = "desktop-protected"))]
        root_admission,
    );
    #[cfg(all(unix, any(target_os = "macos", target_os = "linux")))]
    if transcript.is_err() {
        // Fail-closed recovery: the exact writer never outlives a failed loop.
        runtime
            .terminate_retained_writer()
            .map_err(runtime::map_enrollment_error)?;
    }
    transcript
}
include!("control_v3/transcript.rs");
