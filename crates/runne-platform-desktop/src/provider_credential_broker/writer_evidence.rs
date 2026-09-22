use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterLaunchSpec,
};

use super::WriterProcessEvidence;

#[cfg(unix)]
type DaemonHandoffDigests = ([u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32], [u8; 32]);

impl WriterProcessEvidence {
    #[cfg(unix)]
    pub(crate) fn daemon_handoff_digests(&self) -> Option<DaemonHandoffDigests> {
        match (
            self.release_tuple,
            self.publication_public_key,
            self.writer_kill_public_key,
        ) {
            (Some(release_tuple), Some(publication_public_key), Some(writer_kill_public_key))
                if self.is_daemon_bound() =>
            {
                Some((
                    self.start,
                    self.image,
                    release_tuple,
                    self.channel,
                    publication_public_key,
                    writer_kill_public_key,
                ))
            }
            _ => None,
        }
    }

    /// Returns whether daemon-bound evidence matches one exact verified writer launch.
    #[must_use]
    pub fn matches_daemon_owned_launch(
        &self,
        launch: &VerifiedWriterLaunchSpec,
        expected_channel: [u8; 32],
        expected_publication_public_key: [u8; 32],
    ) -> bool {
        self.is_daemon_bound()
            && self.channel == expected_channel
            && self.publication_public_key == Some(expected_publication_public_key)
            && self.image == launch.artifact().image_digest()
            && self.release_tuple == Some(launch.artifact().release_tuple_digest())
    }
}

impl std::fmt::Debug for WriterProcessEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WriterProcessEvidence(<native-only>)")
    }
}

impl WriterProcessEvidence {
    #[cfg(target_os = "macos")]
    pub(super) fn from_verified_macos_writer(
        start: [u8; 32],
        image: [u8; 32],
        release_tuple: [u8; 32],
        channel: [u8; 32],
        publication_public_key: [u8; 32],
        writer_kill_public_key: [u8; 32],
    ) -> Result<Self, BrokerHandoffError> {
        Self::new_daemon_bound(
            start,
            image,
            release_tuple,
            channel,
            publication_public_key,
            writer_kill_public_key,
        )
    }

    #[cfg(unix)]
    pub(super) fn new_daemon_bound(
        start: [u8; 32],
        image: [u8; 32],
        release_tuple: [u8; 32],
        channel: [u8; 32],
        publication_public_key: [u8; 32],
        writer_kill_public_key: [u8; 32],
    ) -> Result<Self, BrokerHandoffError> {
        let evidence = Self {
            start,
            image,
            channel,
            release_tuple: Some(release_tuple),
            publication_public_key: Some(publication_public_key),
            writer_kill_public_key: Some(writer_kill_public_key),
        };
        evidence
            .is_daemon_bound()
            .then_some(evidence)
            .ok_or(BrokerHandoffError::Rejected)
    }

    #[cfg(test)]
    pub(super) const fn test_only(
        start_identity: [u8; 32],
        image_identity: [u8; 32],
        channel_identity: [u8; 32],
    ) -> Self {
        Self {
            start: start_identity,
            image: image_identity,
            channel: channel_identity,
            release_tuple: None,
            publication_public_key: None,
            writer_kill_public_key: None,
        }
    }

    #[cfg(test)]
    pub(super) const fn test_only_daemon(
        start_identity: [u8; 32],
        image_identity: [u8; 32],
        release_tuple_digest: [u8; 32],
        channel_identity: [u8; 32],
        publication_public_key: [u8; 32],
        writer_kill_public_key: [u8; 32],
    ) -> Self {
        Self {
            start: start_identity,
            image: image_identity,
            channel: channel_identity,
            release_tuple: Some(release_tuple_digest),
            publication_public_key: Some(publication_public_key),
            writer_kill_public_key: Some(writer_kill_public_key),
        }
    }
    pub(super) fn is_complete(&self) -> bool {
        self.start != [0; 32] && self.image != [0; 32] && self.channel != [0; 32]
    }
    pub(super) fn is_daemon_bound(&self) -> bool {
        self.is_complete()
            && self.release_tuple.is_some_and(|digest| digest != [0; 32])
            && self
                .publication_public_key
                .is_some_and(|public_key| public_key != [0; 32])
            && self
                .writer_kill_public_key
                .is_some_and(|public_key| public_key != [0; 32])
    }

    /// Returns the fresh one-shot binding accepted by the native handoff.
    #[must_use]
    pub const fn channel_binding(&self) -> [u8; 32] {
        self.channel
    }
}
