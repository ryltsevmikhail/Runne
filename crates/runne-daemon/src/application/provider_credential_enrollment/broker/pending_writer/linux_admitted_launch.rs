//! Signed installed-tuple admission immediately before daemon-owned Linux Pair spawn.

use std::os::unix::net::UnixStream;

use runne_api::{CredentialBrokerTransferAuthenticator, ProtectedActivationKeys};
use runne_platform_desktop::{
    VerifiedInstalledLinuxEnrollmentMeasurementFacts, VerifiedInstalledLinuxWriterCapability,
    provider_credential_broker::{
        LinuxAuthenticatedPairSecretRelay, prepare_daemon_owned_writer_endpoint_handoff,
        send_daemon_owned_writer_endpoint, spawn_linux_pair_writer_from_prepared_handoff,
        spawn_linux_writer_from_prepared_handoff,
    },
};
use runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec;

use super::super::unix_linux::LinuxCredentialBrokerChannel;
use super::{
    LinuxWriterLaunchInputs, launch_linux_control_writer_with_handshake,
    launch_linux_pair_writer_with_handshake,
};
use crate::application::provider_credential_enrollment::broker::pending::PendingBrokerEndpointHandoff;

/// Private launch spec whose only production constructor consumes signed installed evidence.
struct VerifiedLinuxWriterLaunchSpec(VerifiedWriterLaunchSpec);

impl VerifiedLinuxWriterLaunchSpec {
    fn from_installed(
        capability: &VerifiedInstalledLinuxWriterCapability,
        stream: &UnixStream,
    ) -> Option<(Self, VerifiedInstalledLinuxEnrollmentMeasurementFacts)> {
        let facts = capability.measurement_facts(stream)?;
        let spec = capability.writer_launch_spec(stream)?;
        if spec.artifact().image_digest() != facts.writer()
            || spec.artifact().release_tuple_digest() != facts.release_tuple()
        {
            return None;
        }
        Some((Self(spec), facts))
    }
}

#[allow(
    clippy::type_complexity,
    reason = "the tuple keeps one-shot writer authority and its measured release facts together"
)]
pub(crate) fn launch_verified_linux_pair_writer(
    handoff: PendingBrokerEndpointHandoff,
    capability: &VerifiedInstalledLinuxWriterCapability,
    stream: &UnixStream,
    keys: &ProtectedActivationKeys,
    launch_secret: [u8; 32],
) -> Result<
    (
        LinuxCredentialBrokerChannel,
        LinuxAuthenticatedPairSecretRelay,
        VerifiedInstalledLinuxEnrollmentMeasurementFacts,
        [u8; 32],
        [u8; 32],
    ),
    runne_api::ProviderCredentialEnrollmentHostError,
> {
    let (spec, facts) = VerifiedLinuxWriterLaunchSpec::from_installed(capability, stream)
        .ok_or(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)?;
    let (binding, rendezvous, control_end_for_writer, transfer_authority) =
        handoff.into_linux_writer_parts()?;
    if binding.release_tuple.as_bytes() != facts.release_tuple() {
        return Err(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied);
    }
    let daemon_image = facts.daemon();
    let channel_binding = rendezvous.channel_binding();
    let publication_key = rendezvous.publication_public_key();
    let authenticator = CredentialBrokerTransferAuthenticator::from_protected_activation(keys);
    let spawn_authenticator = authenticator.clone();
    let spec_for_spawn = spec.0.clone();
    let (channel, relay) = launch_linux_pair_writer_with_handshake(
        LinuxWriterLaunchInputs {
            rendezvous,
            control_end_for_writer,
            binding,
            transfer_authority,
            launch_secret,
            daemon_image,
        },
        &spec.0,
        &authenticator,
        Box::new(move |control, startup, transfer, auth| {
            let (sender, receiver) = UnixStream::pair()
                .map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::Unavailable)?;
            let prepared = prepare_daemon_owned_writer_endpoint_handoff(
                receiver,
                auth,
                channel_binding,
                publication_key,
            )
            .map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)?;
            std::thread::scope(|scope| {
                let sender_task = scope.spawn(|| {
                    send_daemon_owned_writer_endpoint(
                        sender,
                        control,
                        transfer,
                        channel_binding,
                        publication_key,
                    )
                });
                let spawned = spawn_linux_pair_writer_from_prepared_handoff(
                    &spec_for_spawn,
                    prepared,
                    startup,
                    &spawn_authenticator,
                );
                let sent = match sender_task.join() {
                    Ok(Ok(_facts)) => Ok(()),
                    Ok(Err(_)) => {
                        Err(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)
                    }
                    Err(_) => Err(runne_api::ProviderCredentialEnrollmentHostError::Unavailable),
                };
                match (sent, spawned) {
                    (Ok(()), Ok(spawned)) => Ok(spawned),
                    (_, Ok((mut process, relay))) => {
                        use runne_platform_desktop::provider_credential_broker::RetainedWriterProcess as _;
                        let _ = process.terminate_retained_child();
                        let _ = process.reap_retained_child();
                        drop(relay);
                        Err(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)
                    }
                    (Err(error), Err(_)) => Err(error),
                    (Ok(()), Err(_)) => {
                        Err(runne_api::ProviderCredentialEnrollmentHostError::Unavailable)
                    }
                }
            })
        }),
    )?;
    Ok((channel, relay, facts, channel_binding, publication_key))
}

pub(crate) fn launch_verified_linux_control_writer(
    handoff: PendingBrokerEndpointHandoff,
    capability: &VerifiedInstalledLinuxWriterCapability,
    stream: &UnixStream,
    keys: &ProtectedActivationKeys,
    launch_secret: [u8; 32],
) -> Result<
    (
        LinuxCredentialBrokerChannel,
        VerifiedInstalledLinuxEnrollmentMeasurementFacts,
        [u8; 32],
        [u8; 32],
    ),
    runne_api::ProviderCredentialEnrollmentHostError,
> {
    let (spec, facts) = VerifiedLinuxWriterLaunchSpec::from_installed(capability, stream)
        .ok_or(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)?;
    let (binding, rendezvous, control_end_for_writer, transfer_authority) =
        handoff.into_linux_writer_parts()?;
    if binding.release_tuple.as_bytes() != facts.release_tuple() {
        return Err(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied);
    }
    let daemon_image = facts.daemon();
    let channel_binding = rendezvous.channel_binding();
    let publication_key = rendezvous.publication_public_key();
    let authenticator = CredentialBrokerTransferAuthenticator::from_protected_activation(keys);
    let spec_for_spawn = spec.0.clone();
    let channel = launch_linux_control_writer_with_handshake(
        LinuxWriterLaunchInputs {
            rendezvous,
            control_end_for_writer,
            binding,
            transfer_authority,
            launch_secret,
            daemon_image,
        },
        &spec.0,
        &authenticator,
        Box::new(move |control, startup, transfer, auth| {
            let (sender, receiver) = UnixStream::pair()
                .map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::Unavailable)?;
            let prepared = prepare_daemon_owned_writer_endpoint_handoff(
                receiver,
                auth,
                channel_binding,
                publication_key,
            )
            .map_err(|_| runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)?;
            std::thread::scope(|scope| {
                let sender_task = scope.spawn(|| {
                    send_daemon_owned_writer_endpoint(
                        sender,
                        control,
                        transfer,
                        channel_binding,
                        publication_key,
                    )
                });
                let spawned = spawn_linux_writer_from_prepared_handoff(
                    &spec_for_spawn,
                    prepared,
                    startup,
                    auth,
                );
                let sent = match sender_task.join() {
                    Ok(Ok(_facts)) => Ok(()),
                    Ok(Err(_)) => {
                        Err(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)
                    }
                    Err(_) => Err(runne_api::ProviderCredentialEnrollmentHostError::Unavailable),
                };
                match (sent, spawned) {
                    (Ok(()), Ok(process)) => Ok(process),
                    (_, Ok(mut process)) => {
                        use runne_platform_desktop::provider_credential_broker::RetainedWriterProcess as _;
                        let _ = process.terminate_retained_child();
                        let _ = process.reap_retained_child();
                        Err(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)
                    }
                    (Err(error), Err(_)) => Err(error),
                    (Ok(()), Err(_)) => {
                        Err(runne_api::ProviderCredentialEnrollmentHostError::Unavailable)
                    }
                }
            })
        }),
    )?;
    Ok((channel, facts, channel_binding, publication_key))
}
