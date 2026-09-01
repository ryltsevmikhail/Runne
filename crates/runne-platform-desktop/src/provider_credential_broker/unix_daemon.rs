#[cfg(not(target_os = "macos"))]
use std::os::unix::net::UnixStream;

use runne_platform_ports::provider_credential_broker::BrokerHandoffError;
#[cfg(any(not(target_os = "macos"), test))]
use runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec;

use super::PreparedDaemonWriterEndpointHandoff;
#[cfg(any(not(target_os = "macos"), test))]
use super::UnixRetainedWriterProcess;

#[cfg(target_os = "macos")]
use crate::{VerifiedMacOsWriterLaunch, provider_credential_broker::macos_writer_admission};

/// Launches the fixed writer with its prepared daemon handoff transport.
///
/// The macOS launch uses an atomic close-on-exec-default spawn profile. Other
/// Unix targets fail closed until they have an equivalent close-other-fds
/// primitive, so no ambient descriptor can reach the writer.
///
/// # Errors
///
/// Returns a closed failure when the exact native launch profile is unavailable.
#[cfg(not(target_os = "macos"))]
pub fn spawn_unix_writer_from_prepared_daemon_handoff(
    spec: &VerifiedWriterLaunchSpec,
    prepared: PreparedDaemonWriterEndpointHandoff,
) -> Result<UnixRetainedWriterProcess, BrokerHandoffError> {
    let (transport, _, _) = prepared.into_spawn_parts();
    spawn_prepared_writer(spec, transport)
}

/// Launches and live-verifies one macOS writer from a signed release tuple.
///
/// # Errors
///
/// Returns a closed failure when spawn, retained identity, live code signing,
/// executable bytes, or daemon handoff bindings do not match exactly.
#[cfg(target_os = "macos")]
pub fn spawn_macos_verified_writer_from_prepared_daemon_handoff(
    launch: VerifiedMacOsWriterLaunch,
    prepared: PreparedDaemonWriterEndpointHandoff,
) -> Result<macos_writer_admission::VerifiedMacOsWriterProcess, BrokerHandoffError> {
    let (transport, channel_binding, publication_public_key) = prepared.into_spawn_parts();
    let image = macos_writer_admission::prepare_retained_writer_image(&launch)?;
    let (process, secret_writer) = super::unix_daemon_macos::spawn_macos_prepared_writer(
        launch.launch(),
        &image,
        transport,
        None,
    )?;
    debug_assert!(secret_writer.is_none());
    macos_writer_admission::VerifiedMacOsWriterProcess::admit(
        process,
        launch,
        image,
        channel_binding,
        publication_public_key,
    )
}

/// Launches and live-verifies a Pair writer with one authenticated secret relay.
///
/// # Errors
///
/// Returns a closed failure when the authenticated handoff, secret pipe,
/// direct spawn, or retained writer admission cannot be completed exactly.
#[cfg(target_os = "macos")]
pub fn spawn_macos_verified_pair_writer_from_prepared_daemon_handoff(
    launch: VerifiedMacOsWriterLaunch,
    prepared: PreparedDaemonWriterEndpointHandoff,
) -> Result<
    (
        macos_writer_admission::VerifiedMacOsWriterProcess,
        super::macos_secret_pipe::MacOsAuthenticatedPairSecretRelay,
    ),
    BrokerHandoffError,
> {
    let (transport, channel_binding, publication_public_key, sealer) =
        prepared.into_pair_spawn_parts()?;
    let image = macos_writer_admission::prepare_retained_writer_image(&launch)?;
    let pipe = super::macos_secret_pipe::PreparedMacOsPairSecretPipe::prepare()?;
    let (process, writer) = super::unix_daemon_macos::spawn_macos_prepared_writer(
        launch.launch(),
        &image,
        transport,
        Some(pipe),
    )?;
    let admitted = macos_writer_admission::VerifiedMacOsWriterProcess::admit(
        process,
        launch,
        image,
        channel_binding,
        publication_public_key,
    )?;
    let relay =
        super::macos_secret_pipe::MacOsAuthenticatedPairSecretRelay::from_authenticated_parts(
            sealer,
            writer.ok_or(BrokerHandoffError::Rejected)?,
        );
    Ok((admitted, relay))
}

#[cfg(not(target_os = "macos"))]
fn spawn_prepared_writer(
    _spec: &VerifiedWriterLaunchSpec,
    _transport: UnixStream,
) -> Result<UnixRetainedWriterProcess, BrokerHandoffError> {
    Err(BrokerHandoffError::Unavailable)
}

#[cfg(all(test, target_os = "macos"))]
pub(super) fn spawn_test_macos_prepared_writer(
    spec: &VerifiedWriterLaunchSpec,
    prepared: PreparedDaemonWriterEndpointHandoff,
) -> Result<UnixRetainedWriterProcess, BrokerHandoffError> {
    let (transport, _, _) = prepared.into_spawn_parts();
    let image = super::macos_writer_admission::test_retained_writer_image(spec.executable())?;
    super::unix_daemon_macos::spawn_macos_prepared_writer(spec, &image, transport, None)
        .map(|(process, _)| process)
}
