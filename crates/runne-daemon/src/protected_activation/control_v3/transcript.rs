#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
#[cfg_attr(not(unix), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
fn serve_v3_transcript(
    channel: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    owned_launch: &mut ProtectedCredentialEnrollmentOwnedLaunchV3,
    local_session_service: &Arc<Mutex<LocalSessionService>>,
    session_clock: &Arc<dyn Fn() -> Duration + Send + Sync>,
    ticket_clock: &TicketClock,
    #[cfg(unix)] runtime: &mut V3EnrollmentRuntime,
    #[cfg(all(unix, feature = "desktop-protected"))] root_admission: Option<
        Arc<crate::protected_activation::ProtectedRootControl>,
    >,
) -> Result<(), LaunchAuthorityError> {
    let mut last_renew_sequence = 0_u64;
    #[cfg(all(unix, feature = "desktop-protected"))]
    let mut last_root_sequence = 0_u64;
    #[cfg(all(unix, feature = "desktop-protected"))]
    let mut used_root_transfers = std::collections::VecDeque::new();
    loop {
        #[cfg(target_os = "macos")]
        if runtime.yield_for_credential_service_rejoin(channel, keys, owned_launch)? {
            continue;
        }
        #[cfg(target_os = "macos")]
        let frame = match runtime.deferred_control.take() {
            Some(frame) => frame,
            None => channel.read_control_frame()?,
        };
        #[cfg(not(target_os = "macos"))]
        let frame = channel.read_control_frame()?;
        #[cfg(all(unix, target_os = "macos"))]
        if runne_api::ProtectedCredentialDiscoveryCodec::recognizes_frame(&frame) {
            runtime.discover_cleanup(channel, keys, owned_launch, local_session_service, &frame)?;
            continue;
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if runne_api::ProtectedCredentialRoundCodec::recognizes_frame(&frame) {
            runtime.begin_next_round(channel, keys, owned_launch, local_session_service, &frame)?;
            continue;
        }
        #[cfg(target_os = "linux")]
        if runne_api::ProtectedCredentialRoundCodec::recognizes_frame(&frame) {
            runtime.begin_next_linux_round(
                channel,
                keys,
                owned_launch,
                local_session_service,
                &frame,
            )?;
            continue;
        }
        #[cfg(all(unix, feature = "desktop-protected"))]
        if let Some(sequence) =
            crate::protected_activation::dispatch_root_handle_control_frame_for_ids(
                channel,
                &frame,
                keys,
                owned_launch.launch_authority_id(),
                owned_launch.session_id(),
                owned_launch.launch_generation(),
                &mut used_root_transfers,
                last_root_sequence,
                runtime::unix_now_millis()?,
                root_admission.as_deref(),
            )?
        {
            last_root_sequence = sequence;
            continue;
        }
        if let Ok(renewal) = ProtectedCredentialEnrollmentRenewRequestV3::decode_frame(&frame) {
            #[cfg(unix)]
            if !enrollment_transcript_allows_rotation(runtime.has_session(), runtime.terminal) {
                return Err(LaunchAuthorityError::OwnershipMismatch);
            }
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            if let Some(session) = runtime.session.as_ref() {
                session
                    .require_durable_terminal()
                    .map_err(runtime::map_enrollment_error)?;
                session.clear_http_facts();
            }
            #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
            let idle_rendezvous = if let Some(session) = runtime.session.as_mut() {
                if session.is_idle() {
                    let rendezvous = Some(
                        session
                            .take_idle_rendezvous()
                            .map_err(runtime::map_enrollment_error)?,
                    );
                    runtime.session.take();
                    rendezvous
                } else {
                    session
                        .require_durable_terminal()
                        .map_err(runtime::map_enrollment_error)?;
                    session.clear_http_facts();
                    None
                }
            } else {
                None
            };
            // Fence the root admission authority exactly like the V2 renewal
            // path: no rotated successor authority may outrun an in-flight
            // root handle handoff that predates the rotation.
            #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
            if let Some(authority) = &root_admission {
                authority
                    .fence()
                    .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            }
            let next_owned_launch = renewal::rotate(
                channel,
                keys,
                owned_launch,
                local_session_service,
                session_clock,
                ticket_clock,
                &renewal,
                last_renew_sequence,
            )?;
            #[cfg(all(target_os = "linux", feature = "desktop-protected"))]
            if let Some(rendezvous) = idle_rendezvous {
                let control = runtime
                    .linux_control
                    .as_ref()
                    .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
                control
                    .rebind_idle_linux_preadmission(
                        *owned_launch.session_id(),
                        *next_owned_launch.session_id(),
                    )
                    .map_err(runtime::map_enrollment_error)?;
                let session = control
                    .start_protected_session(keys, &next_owned_launch, rendezvous)
                    .map_err(runtime::map_enrollment_error)?;
                runtime.live = Some(live_session::LiveEnrollmentSession::capture(
                    local_session_service,
                    &next_owned_launch,
                )?);
                runtime.session = Some(session);
                runtime.round_previous = Some(next_owned_launch.clone());
            }
            #[cfg(all(
                feature = "desktop-protected",
                any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))
            ))]
            if let Some(session) = runtime.session.as_mut() {
                session
                    .refresh_http_facts(&next_owned_launch)
                    .map_err(runtime::map_enrollment_error)?;
            }
            last_renew_sequence = renewal.sequence();
            *owned_launch = next_owned_launch;
            continue;
        }
        if let Ok(shutdown) = ProtectedCredentialEnrollmentShutdownV3::decode_frame(&frame) {
            shutdown.verify_exact(owned_launch, keys)?;
            #[cfg(unix)]
            runtime.require_shutdown()?;
            let mut acknowledgement =
                ProtectedCredentialEnrollmentShutdownAckV3::new(owned_launch.clone(), true);
            acknowledgement.sign(keys);
            #[cfg(unix)]
            write_shutdown_ack_after_revocation(runtime, channel, &acknowledgement)?;
            #[cfg(not(unix))]
            channel.write_control_frame(
                &acknowledgement
                    .encode_frame()
                    .map_err(|_| LaunchAuthorityError::InvalidContract)?,
            )?;
            return Ok(());
        }
        #[cfg(target_os = "linux")]
        {
            linux_round::run_linux_initial_exchange(
                runtime,
                channel,
                keys,
                owned_launch,
                local_session_service,
                frame,
            )?;
            continue;
        }
        #[cfg(not(target_os = "linux"))]
        return Err(LaunchAuthorityError::InvalidContract);
    }
}

#[cfg(all(unix, target_os = "macos", target_arch = "aarch64"))]
fn write_shutdown_ack_after_revocation(
    runtime: &mut V3EnrollmentRuntime,
    channel: &mut ProtectedActivationChannel,
    acknowledgement: &ProtectedCredentialEnrollmentShutdownAckV3,
) -> Result<(), LaunchAuthorityError> {
    drop(runtime.revoke_shutdown_authorization());
    channel.write_control_frame(
        &acknowledgement
            .encode_frame()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
    )
}

#[cfg(all(
    unix,
    not(all(target_os = "macos", target_arch = "aarch64")),
    feature = "desktop-protected"
))]
fn write_shutdown_ack_after_revocation(
    runtime: &mut V3EnrollmentRuntime,
    channel: &mut ProtectedActivationChannel,
    acknowledgement: &ProtectedCredentialEnrollmentShutdownAckV3,
) -> Result<(), LaunchAuthorityError> {
    runtime.revoke_shutdown_authorization();
    channel.write_control_frame(
        &acknowledgement
            .encode_frame()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
    )
}

#[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
#[path = "transcript/shutdown_tests.rs"]
mod shutdown_tests;
