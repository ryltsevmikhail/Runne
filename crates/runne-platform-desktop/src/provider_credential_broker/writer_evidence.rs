use runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec;

use super::WriterProcessEvidence;

impl WriterProcessEvidence {
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
