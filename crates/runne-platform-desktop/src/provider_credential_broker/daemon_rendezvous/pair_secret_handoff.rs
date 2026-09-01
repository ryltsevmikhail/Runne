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
