#![cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]

use super::*;
#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "desktop-protected"
))]
#[path = "credential_status.rs"]
mod credential_status;

include!("control_v1.rs");

#[cfg(all(
    target_os = "macos",
    target_arch = "aarch64",
    feature = "desktop-protected"
))]
#[path = "control_status_guard.rs"]
mod status_guard;

#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
pub(crate) fn run_control_loop_v2(
    mut channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    mut owned_launch: ProtectedOwnedLaunchV2,
    local_session_service: Arc<Mutex<LocalSessionService>>,
    session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
    #[cfg(feature = "desktop-protected")] root_admission: Option<Arc<ProtectedRootControl>>,
    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    ))]
    enrollment_transition: Option<(
        super::enrollment_control_transition::EnrollmentControlComposition,
        super::installation_anchor::VerifiedNativeEnrollmentInstallation,
    )>,
) -> Result<(), LaunchAuthorityError> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    let mut status_guard =
        status_guard::SessionRevocationGuard::new(*owned_launch.session_id(), |session| {
            if let Some((composition, _)) = enrollment_transition.as_ref()
                && let Some(control) = composition.enrollment_control.as_ref()
            {
                control.clear_http_facts(session);
            }
        });
    channel.enter_control_loop()?;
    let mut last_renew_sequence = 0_u64;
    #[cfg(all(any(unix, windows), feature = "desktop-protected"))]
    let mut last_root_sequence = 0_u64;
    #[cfg(all(any(unix, windows), feature = "desktop-protected"))]
    let mut used_root_transfers = std::collections::VecDeque::new();
    loop {
        let frame = channel.read_control_frame()?;
        #[cfg(all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        ))]
        if runne_api::ProtectedCredentialDiscoveryCodec::recognizes_frame(&frame) {
            super::startup_discovery::respond(
                &mut channel,
                &keys,
                &owned_launch,
                &local_session_service,
                enrollment_transition.as_ref(),
                &frame,
            )?;
            continue;
        }
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        if let Some((composition, _)) = enrollment_transition.as_ref()
            && runne_api::ProtectedCredentialStatusRequestV2::decode_frame(&frame).is_ok()
        {
            last_root_sequence = credential_status::respond(
                &mut channel,
                &keys,
                &owned_launch,
                &local_session_service,
                composition,
                &frame,
                last_root_sequence,
            )?;
            continue;
        }
        #[cfg(all(
            target_os = "macos",
            target_arch = "aarch64",
            feature = "desktop-protected"
        ))]
        if let Some((composition, installation)) = enrollment_transition.as_ref()
            && let Ok(prepare) =
                runne_api::ProtectedCredentialEnrollmentPrepareV2::decode_frame(&frame)
        {
            let outcome = super::enrollment_control_transition::run_enrollment_control_exchange(
                &mut channel,
                &prepare,
                &keys,
                &owned_launch,
                composition,
                &local_session_service,
                &session_clock,
                installation,
            )?;
            let (v3_keys, v3_owned_launch, rendezvous, installed_facts) = outcome.into_parts();
            drop(status_guard);
            return super::control_v3::run_control_loop_v3_entered(
                channel,
                v3_keys,
                v3_owned_launch,
                local_session_service,
                session_clock,
                composition.ticket_clock(),
                super::control_v3::V3EnrollmentDispatch::new(
                    composition.enrollment_control.clone(),
                    rendezvous,
                    installed_facts,
                )
                .with_round_profile(composition.profile_directory.clone(), installation),
            );
        }
        #[cfg(all(any(unix, windows), feature = "desktop-protected"))]
        if let Some(sequence) = dispatch_root_handle_control_frame(
            &mut channel,
            &frame,
            &keys,
            owned_launch.compatibility_owned_launch(),
            &mut used_root_transfers,
            last_root_sequence,
            unix_millis()?,
            root_admission.as_deref(),
        )? {
            last_root_sequence = sequence;
            continue;
        }
        if let Ok(renewal) = ProtectedRenewRequestV2::decode_frame(&frame) {
            renewal.verify_exact(&owned_launch, last_renew_sequence, &keys)?;
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            status_guard.revoke();
            #[cfg(feature = "desktop-protected")]
            if let Some(authority) = &root_admission {
                authority
                    .fence()
                    .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            }
            let current = local_session_service
                .lock()
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?
                .current_binding()
                .clone();
            let mut next_session_id = *uuid::Uuid::now_v7().as_bytes();
            while next_session_id == *current.ephemeral().session_id()
                || next_session_id == current.ephemeral().daemon_instance_id().into_bytes()
            {
                next_session_id = *uuid::Uuid::now_v7().as_bytes();
            }
            let mut bootstrap_ticket = random_control_secret();
            let issued_at = session_clock();
            let expires_at = issued_at
                .checked_add(Duration::from_secs(30))
                .ok_or(LaunchAuthorityError::RenewalUnavailable)?;
            let next_binding = RuntimeSessionBinding::new(
                current.stable().clone(),
                current.ephemeral().daemon_instance_id(),
                current.ephemeral().launch_generation(),
                next_session_id,
                current.ephemeral().authorization_epoch(),
                current.ephemeral().sensitivity_ceiling(),
                *current.certificate_sha256(),
            )
            .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            local_session_service
                .lock()
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?
                .rotate_protected_bootstrap(next_binding, bootstrap_ticket, issued_at, expires_at)
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            let mut ticket = ProtectedRenewTicketV2::new(
                &renewal,
                next_session_id,
                bootstrap_ticket,
                u64::try_from(issued_at.as_millis())
                    .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?,
                u64::try_from(expires_at.as_millis())
                    .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?,
            )?;
            bootstrap_ticket.zeroize();
            ticket.sign(&keys);
            channel.write_control_frame(
                &ticket
                    .encode_frame()
                    .map_err(|_| LaunchAuthorityError::InvalidContract)?,
            )?;
            last_renew_sequence = renewal.sequence();
            owned_launch = ticket.next_owned_launch();
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            status_guard.track(*owned_launch.session_id());
            continue;
        }
        let shutdown = ProtectedShutdownV2::decode_frame(&frame)
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        shutdown.verify_exact(&owned_launch, &keys)?;
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        status_guard.revoke();
        let mut acknowledgement = ProtectedShutdownAckV2::new(owned_launch.clone(), true);
        acknowledgement.sign(&keys);
        channel.write_control_frame(
            &acknowledgement
                .encode_frame()
                .map_err(|_| LaunchAuthorityError::InvalidContract)?,
        )?;
        return Ok(());
    }
}

#[cfg(all(any(unix, windows), feature = "desktop-protected"))]
fn unix_millis() -> Result<u64, LaunchAuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|value| u64::try_from(value.as_millis()).ok())
        .ok_or(LaunchAuthorityError::StaleLaunchAuthority)
}
