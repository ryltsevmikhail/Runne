use std::os::unix::net::UnixStream;

use super::PreparedDaemonWriterEndpointHandoff;

/// Move-only authority minted only while consuming the authenticated handoff.
pub(in crate::provider_credential_broker) struct AuthenticatedPairSecretHandoff {
    channel_binding: [u8; 32],
    publication_public_key: [u8; 32],
}

impl AuthenticatedPairSecretHandoff {
    pub(in crate::provider_credential_broker) const fn into_relay_facts(
        self,
    ) -> ([u8; 32], [u8; 32]) {
        (self.publication_public_key, self.channel_binding)
    }
}

impl PreparedDaemonWriterEndpointHandoff {
    pub(in crate::provider_credential_broker) fn into_pair_spawn_parts(
        self,
    ) -> (
        UnixStream,
        [u8; 32],
        [u8; 32],
        super::super::macos_secret_sealer::AuthenticatedPairSecretSealer,
    ) {
        let sealer = super::super::macos_secret_sealer::AuthenticatedPairSecretSealer::from_handoff(
            AuthenticatedPairSecretHandoff {
                channel_binding: self.channel_binding,
                publication_public_key: self.publication_public_key,
            },
        );
        (
            self.transport,
            self.channel_binding,
            self.publication_public_key,
            sealer,
        )
    }
}

#[cfg(target_os = "linux")]
impl PreparedDaemonWriterEndpointHandoff {
    pub(in crate::provider_credential_broker) fn into_linux_pair_spawn_parts(
        self,
        authenticator: &runne_api::CredentialBrokerTransferAuthenticator,
    ) -> Result<
        (
            UnixStream,
            super::super::macos_secret_sealer::AuthenticatedPairSecretSealer,
        ),
        runne_platform_ports::provider_credential_broker::BrokerHandoffError,
    > {
        let challenge = self.challenge;
        let (transport, channel, key, sealer) = self.into_pair_spawn_parts();
        // The rendezvous has a half-closed write side. Only the SCM_RIGHTS
        // endpoint is a duplex broker socket. Linux receives it atomically
        // CLOEXEC, verifies the exact response, and only then permits spawn.
        let received = super::receive_prepared::finish_receive(
            transport,
            challenge,
            authenticator,
            channel,
            key,
        )?;
        Ok((received.into_control(), sealer))
    }
}
