use runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec;

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
