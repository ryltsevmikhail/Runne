#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(dead_code)
)]
use std::os::unix::net::UnixStream;
use std::time::Duration;

use rand::{RngCore, rngs::OsRng};
#[cfg(feature = "desktop-protected")]
use runne_api::ProviderCredentialBrokerTransferAuthority;
use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;

const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(feature = "test-support")]
const LOCAL_RENDEZVOUS_TIMEOUT: Duration = Duration::from_mins(2);

/// Daemon-created halves of one pending writer-control rendezvous.
///
/// Tauri receives only the writer endpoint through the authenticated protected
/// control transfer. It never creates this socketpair or reads broker frames.
pub(crate) struct DaemonOwnedUnixBrokerRendezvous {
    daemon: Option<UnixStream>,
    writer: Option<UnixStream>,
    channel_binding: [u8; 32],
    signer: Option<CredentialWriterSessionAttestationSigner>,
    publication_public_key: [u8; 32],
}

/// Opaque daemon-owned endpoint and matching one-shot publication authority.
#[cfg_attr(
    not(feature = "desktop-protected"),
    allow(dead_code, reason = "the protected channel adapter is feature-gated")
)]
pub(crate) struct DaemonBrokerAuthority {
    endpoint: UnixStream,
    channel_binding: [u8; 32],
    signer: Option<CredentialWriterSessionAttestationSigner>,
    publication_public_key: [u8; 32],
}

impl DaemonBrokerAuthority {
    #[cfg(target_os = "macos")]
    pub(crate) const fn endpoint(&self) -> &UnixStream {
        &self.endpoint
    }

    #[cfg(target_os = "macos")]
    pub(in crate::application::provider_credential_enrollment::broker) fn endpoint_mut(
        &mut self,
    ) -> &mut UnixStream {
        &mut self.endpoint
    }

    #[must_use]
    #[cfg(feature = "desktop-protected")]
    pub(crate) const fn channel_binding(&self) -> [u8; 32] {
        self.channel_binding
    }

    #[must_use]
    pub(crate) const fn publication_public_key(&self) -> [u8; 32] {
        self.publication_public_key
    }

    pub(in crate::application::provider_credential_enrollment::broker) fn sign_writer_session(
        &mut self,
        claims: runne_provider::CredentialWriterSessionAttestationClaimsV1,
    ) -> Result<
        (
            runne_provider::SignedCredentialWriterSessionAttestationV1,
            runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        self.signer
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?
            .sign(claims)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    pub(in crate::application::provider_credential_enrollment::broker) fn sign_writer_session_qualified(
        &mut self,
        claims: runne_provider::CredentialWriterSessionAttestationClaimsV1,
        launch_generation: u64,
        context_sha256: [u8; 32],
        ticket_sha256: [u8; 32],
    ) -> Result<
        (
            runne_provider::SignedCredentialWriterSessionAttestationV2,
            runne_provider::CredentialWriterQualifiedPreludeSigner,
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        self.signer
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?
            .sign_qualified(claims, launch_generation, context_sha256, ticket_sha256)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    #[cfg(test)]
    pub(super) fn into_parts(
        mut self,
    ) -> Result<
        (
            UnixStream,
            [u8; 32],
            CredentialWriterSessionAttestationSigner,
            [u8; 32],
        ),
        ProviderCredentialEnrollmentHostError,
    > {
        Ok((
            self.endpoint,
            self.channel_binding,
            self.signer
                .take()
                .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)?,
            self.publication_public_key,
        ))
    }
}

#[cfg_attr(
    all(test, not(target_os = "linux")),
    allow(dead_code, reason = "the descriptor-transfer fixture is Linux-scoped")
)]
#[cfg(test)]
impl DaemonBrokerAuthority {
    pub(super) fn for_test(binding: [u8; 32]) -> Self {
        let (endpoint, _) = UnixStream::pair().unwrap();
        Self::for_test_endpoint(binding, endpoint)
    }

    pub(super) fn for_test_endpoint(binding: [u8; 32], endpoint: UnixStream) -> Self {
        let signer = CredentialWriterSessionAttestationSigner::generate(binding).unwrap();
        let publication_public_key = signer.public_key();
        Self {
            endpoint,
            channel_binding: binding,
            signer: Some(signer),
            publication_public_key,
        }
    }
}

impl DaemonOwnedUnixBrokerRendezvous {
    /// Creates a fresh socketpair owned by the daemon process.
    pub(crate) fn create() -> Result<Self, ProviderCredentialEnrollmentHostError> {
        let (daemon, writer) =
            UnixStream::pair().map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        configure(&daemon)?;
        configure(&writer)?;
        let mut channel_binding = [0; 32];
        OsRng
            .try_fill_bytes(&mut channel_binding)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        if channel_binding == [0; 32] {
            return Err(ProviderCredentialEnrollmentHostError::Unavailable);
        }
        let signer = CredentialWriterSessionAttestationSigner::generate(channel_binding)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        let publication_public_key = signer.public_key();
        Ok(Self {
            daemon: Some(daemon),
            writer: Some(writer),
            channel_binding,
            signer: Some(signer),
            publication_public_key,
        })
    }

    /// Returns the daemon-generated binding for the exact writer channel.
    #[must_use]
    pub(crate) const fn channel_binding(&self) -> [u8; 32] {
        self.channel_binding
    }

    /// Returns the public key that can later verify an inert daemon publication.
    #[must_use]
    pub(crate) fn publication_public_key(&self) -> [u8; 32] {
        self.publication_public_key
    }

    /// Moves endpoint and signing authority together; neither can be obtained twice.
    pub(crate) fn take_daemon_authority(
        &mut self,
    ) -> Result<DaemonBrokerAuthority, ProviderCredentialEnrollmentHostError> {
        if self.daemon.is_none() || self.signer.is_none() {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        Ok(DaemonBrokerAuthority {
            endpoint: self.daemon.take().expect("checked"),
            channel_binding: self.channel_binding,
            signer: self.signer.take(),
            publication_public_key: self.publication_public_key,
        })
    }

    /// Moves the writer endpoint into the authenticated Tauri descriptor transfer once.
    pub(crate) fn take_writer_endpoint(
        &mut self,
    ) -> Result<UnixStream, ProviderCredentialEnrollmentHostError> {
        self.writer
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    /// Sends the writer endpoint only through the authenticated protected control transport.
    #[cfg(feature = "desktop-protected")]
    #[cfg_attr(
        all(test, not(target_os = "linux")),
        allow(dead_code, reason = "descriptor admission is fail-closed off Linux")
    )]
    pub(super) fn handoff_writer_endpoint(
        &mut self,
        transport: UnixStream,
        authority: &ProviderCredentialBrokerTransferAuthority,
    ) -> Result<
        runne_platform_desktop::provider_credential_broker::VerifiedDaemonWriterEndpointHandoffFacts,
        ProviderCredentialEnrollmentHostError,
    >{
        let binding = self.channel_binding;
        let publication_public_key = self.publication_public_key;
        let writer = self.take_writer_endpoint()?;
        runne_platform_desktop::provider_credential_broker::send_daemon_owned_writer_endpoint(
            transport,
            writer,
            authority,
            binding,
            publication_public_key,
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

fn configure(stream: &UnixStream) -> Result<(), ProviderCredentialEnrollmentHostError> {
    #[cfg(feature = "test-support")]
    let timeout = if runne_api::test_support::local_native_enrollment_enabled() {
        LOCAL_RENDEZVOUS_TIMEOUT
    } else {
        RENDEZVOUS_TIMEOUT
    };
    #[cfg(not(feature = "test-support"))]
    let timeout = RENDEZVOUS_TIMEOUT;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
}

#[cfg(test)]
#[path = "../tests/broker_rendezvous.rs"]
mod tests;

#[cfg(all(test, feature = "desktop-protected"))]
#[path = "rendezvous/protected_tests.rs"]
mod protected_tests;
