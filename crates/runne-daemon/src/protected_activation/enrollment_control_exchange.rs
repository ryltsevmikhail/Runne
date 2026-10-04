#![cfg_attr(not(unix), allow(dead_code, unused_imports))]
//! Same-process V2→V3 enrollment control exchange on the entered channel.

//! The exchange is transport-neutral: every daemon-side verification (exact
//! prepare signature, live native peer revalidation, durable `N + 1`
//! reservation, prelude signature, V3 admission, signed readiness) runs
//! unchanged on every unix target. Only the macOS qualification phase inside
//! the V3 loop is platform-gated.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use runne_api::{
    DaemonEnrollmentLaunchPreludeV1, LaunchAuthorityError, ProtectedActivationKeys,
    ProtectedCredentialEnrollmentLaunchRequestV3, ProtectedCredentialEnrollmentPreludeV2,
    ProtectedCredentialEnrollmentPrepareV2, ProtectedCredentialEnrollmentReadyV3,
    ProtectedOwnedLaunchV2, ProtectedReadyV1, RuntimeSessionBinding,
    VerifiedProtectedCredentialEnrollmentPrepareV2,
};
use runne_application::local_session::{LocalSessionError, LocalSessionService};
use zeroize::Zeroizing;

use super::{
    ProtectedActivationChannel,
    enrollment_control_transition::{
        DaemonEnrollmentRendezvous, EnrollmentControlComposition, EnrollmentTransitionOutcome,
    },
};

#[cfg(unix)]
use super::enrollment_transition_v2_v3::{PreparedDaemonEnrollmentTransitionV3, V2TransitionInput};
use crate::application::provider_credential_enrollment::broker::rendezvous::DaemonOwnedUnixBrokerRendezvous;

/// Bounded continuous-clock prelude validity; identical ceiling to launch TTLs.
const ENROLLMENT_PRELUDE_TTL_MILLIS: u64 = 30_000;
const PROTECTED_BOOTSTRAP_TTL: Duration = Duration::from_secs(30);

/// Drives prepare admission, rendezvous creation, exact N+1 reservation,
/// prelude issue, exact V3 admission, and the authoritative rotation on the
/// already-entered channel.
///
/// Every failure terminates the exchange; the caller must terminate the daemon
/// rather than retrying the transition on another authority path.
#[allow(clippy::too_many_arguments)]
#[cfg(all(unix, feature = "desktop-protected"))]
pub(crate) fn run_enrollment_control_exchange_with<F, G>(
    channel: &mut ProtectedActivationChannel,
    prepare: &ProtectedCredentialEnrollmentPrepareV2,
    keys: &ProtectedActivationKeys,
    owned: &ProtectedOwnedLaunchV2,
    composition: &EnrollmentControlComposition,
    sessions: &Arc<Mutex<LocalSessionService>>,
    session_clock: &Arc<dyn Fn() -> Duration + Send + Sync>,
    first_native_verify: F,
    admit_transition: G,
) -> Result<EnrollmentTransitionOutcome, LaunchAuthorityError>
where
    F: FnOnce(&Path, &VerifiedProtectedCredentialEnrollmentPrepareV2<'_>, &UnixStream) -> bool,
    G: FnOnce(
        &V2TransitionInput<'_>,
        ProtectedCredentialEnrollmentLaunchRequestV3,
        &ProtectedActivationChannel,
    ) -> Result<PreparedDaemonEnrollmentTransitionV3, LaunchAuthorityError>,
{
    let claims = prepare.verify_exact_view(owned, 0, keys)?;
    if !first_native_verify(
        &composition.profile_directory,
        &claims,
        channel.unix_stream(),
    ) {
        return Err(LaunchAuthorityError::OwnershipMismatch);
    }
    let rendezvous = DaemonOwnedUnixBrokerRendezvous::create()
        .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
    let binding_digest = rendezvous.channel_binding();
    let publication_key = rendezvous.publication_public_key();
    // The exact successor is reserved durably before any prelude is issued.
    let reserved = lock_service(sessions)?.reserve_protected_enrollment_generation();
    let reserved = map_session_error(reserved)?;
    let now = (composition.ticket_clock)()?;
    let expires = now
        .checked_add(ENROLLMENT_PRELUDE_TTL_MILLIS)
        .ok_or(LaunchAuthorityError::StaleLaunchAuthority)?;
    let prelude_constructor = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        DaemonEnrollmentLaunchPreludeV1::linux_x86_64
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        DaemonEnrollmentLaunchPreludeV1::linux_arm64
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        DaemonEnrollmentLaunchPreludeV1::macos_arm64
    } else {
        return Err(LaunchAuthorityError::UnsupportedPlatformBackend);
    };
    let prelude = prelude_constructor(
        *owned.launch_authority_id(),
        *owned.desktop_host_instance_id(),
        super::random_control_secret(),
        binding_digest,
        publication_key,
        composition.installation_identity_digest,
        *claims.desktop_peer_binding_digest(),
        claims.desktop_supervisor_generation(),
        now,
        expires,
    )?;
    let mut signed_prelude = ProtectedCredentialEnrollmentPreludeV2::new(
        prepare,
        super::random_control_secret(),
        prelude,
    )?;
    signed_prelude.sign(keys);
    write_encoded(
        channel,
        signed_prelude
            .encode_frame()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
    )?;
    let frame = channel.read_control_frame()?;
    let request = ProtectedCredentialEnrollmentLaunchRequestV3::decode_frame(&frame)
        .map_err(|_| LaunchAuthorityError::InvalidContract)?;
    let request_validation_now = (composition.ticket_clock)()?;
    let input = V2TransitionInput::new(
        prepare,
        &signed_prelude,
        owned,
        &composition.original_request,
        0,
        keys,
        now,
        request_validation_now,
        composition.installation_identity_digest,
    );
    let prepared = admit_transition(&input, request, channel)?;
    // The retired V2 HTTP admission facts must not outlive the exchange; only
    // the credential control owns those facts on Linux and macOS.
    #[cfg(all(
        feature = "desktop-protected",
        any(target_os = "linux", all(target_os = "macos", target_arch = "aarch64"))
    ))]
    composition.clear_http_facts(*owned.session_id());
    let next_binding = rotate_to_reserved(
        sessions,
        session_clock,
        reserved,
        prepared.keys().bootstrap_key(),
    )?;
    let ready = build_ready(&prepared, owned, &next_binding, composition, channel)?;
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        let installed_facts = prepared.take_installed_facts();
        Ok(EnrollmentTransitionOutcome::new(
            prepared.keys().clone(),
            ready.owned_launch(),
            DaemonEnrollmentRendezvous::new(rendezvous),
            installed_facts,
        ))
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        Ok(EnrollmentTransitionOutcome::new(
            prepared.keys().clone(),
            ready.owned_launch(),
            DaemonEnrollmentRendezvous::new(rendezvous),
        ))
    }
}

fn lock_service(
    sessions: &Arc<Mutex<LocalSessionService>>,
) -> Result<MutexGuard<'_, LocalSessionService>, LaunchAuthorityError> {
    sessions
        .lock()
        .map_err(|_| LaunchAuthorityError::RenewalUnavailable)
}

fn map_session_error(result: Result<u64, LocalSessionError>) -> Result<u64, LaunchAuthorityError> {
    match result {
        Ok(generation) => Ok(generation),
        Err(LocalSessionError::Unavailable) => Err(LaunchAuthorityError::RenewalUnavailable),
        Err(LocalSessionError::Unauthorized) => Err(LaunchAuthorityError::OwnershipMismatch),
    }
}

fn write_encoded(
    channel: &mut ProtectedActivationChannel,
    frame: Vec<u8>,
) -> Result<(), LaunchAuthorityError> {
    channel.write_control_frame(&Zeroizing::new(frame))
}

/// Rotates the authoritative session onto the exact reserved successor once,
/// raising the authorization epoch by exactly one: the enrollment transition
/// is the only daemon operation that grants local authorization, and every
/// authority issued for the prior epoch dies with this rotation.
fn rotate_to_reserved(
    sessions: &Arc<Mutex<LocalSessionService>>,
    session_clock: &Arc<dyn Fn() -> Duration + Send + Sync>,
    reserved: u64,
    bootstrap_secret: Zeroizing<[u8; 32]>,
) -> Result<RuntimeSessionBinding, LaunchAuthorityError> {
    let current = lock_service(sessions)?.current_binding().clone();
    let mut next_session_id = *uuid::Uuid::now_v7().as_bytes();
    while next_session_id == *current.ephemeral().session_id()
        || next_session_id == current.ephemeral().daemon_instance_id().into_bytes()
    {
        next_session_id = *uuid::Uuid::now_v7().as_bytes();
    }
    let Some(next_epoch) = current.ephemeral().authorization_epoch().checked_add(1) else {
        return Err(LaunchAuthorityError::RenewalUnavailable);
    };
    let next_binding = RuntimeSessionBinding::new(
        current.stable().clone(),
        current.ephemeral().daemon_instance_id(),
        reserved,
        next_session_id,
        next_epoch,
        current.ephemeral().sensitivity_ceiling(),
        *current.certificate_sha256(),
    )
    .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
    let issued_at = session_clock();
    let expires_at = issued_at
        .checked_add(PROTECTED_BOOTSTRAP_TTL)
        .ok_or(LaunchAuthorityError::RenewalUnavailable)?;
    let rotated = lock_service(sessions)?.rotate_protected_enrollment_epoch(
        &current,
        next_binding.clone(),
        *bootstrap_secret,
        issued_at,
        expires_at,
    );
    map_session_error(rotated.map(|()| reserved))?;
    Ok(next_binding)
}

/// Builds, signs, and writes the V3 readiness bound to the rotated session.
#[cfg(all(unix, feature = "desktop-protected"))]
fn build_ready(
    prepared: &PreparedDaemonEnrollmentTransitionV3,
    owned: &ProtectedOwnedLaunchV2,
    next_binding: &RuntimeSessionBinding,
    composition: &EnrollmentControlComposition,
    channel: &mut ProtectedActivationChannel,
) -> Result<ProtectedCredentialEnrollmentReadyV3, LaunchAuthorityError> {
    let request = prepared
        .enrollment()
        .ok_or(LaunchAuthorityError::InvalidContract)?;
    let ready = ProtectedReadyV1::new(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        request.executable().clone(),
        request.profile().clone(),
        owned.compatibility_owned_launch().stable().clone(),
        next_binding.ephemeral().daemon_instance_id().into_bytes(),
        next_binding.ephemeral().launch_generation(),
        *next_binding.ephemeral().session_id(),
        composition.endpoint.clone(),
        composition.certificate_sha256,
        composition.certificate_der.clone(),
        composition.capabilities.clone(),
    )
    .map_err(|_| LaunchAuthorityError::InvalidContract)?;
    let mut ready = ProtectedCredentialEnrollmentReadyV3::new(
        ready,
        request.provider_binding().clone(),
        request.enrollment_binding().clone(),
        composition.provider_readiness,
    )
    .map_err(|_| LaunchAuthorityError::InvalidContract)?;
    ready.sign(request, prepared.keys())?;
    write_encoded(
        channel,
        ready
            .encode_frame()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
    )?;
    Ok(ready)
}
