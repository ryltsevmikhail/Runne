use super::ReceivedWriterProcessMeasurements;

/// Constructor-sealed facts authenticated by the exact native evidence exchange.
pub struct VerifiedWriterMeasurementFacts {
    start: [u8; 32],
    image: [u8; 32],
    release_tuple: [u8; 32],
    channel: [u8; 32],
    publication_public_key: [u8; 32],
    writer_kill_public_key: [u8; 32],
}

impl ReceivedWriterProcessMeasurements {
    /// Retains authenticated facts while the one-use witness enters kernel capture.
    #[must_use]
    pub(in crate::provider_credential_broker) const fn verified_facts(
        &self,
    ) -> VerifiedWriterMeasurementFacts {
        VerifiedWriterMeasurementFacts {
            start: self.start,
            image: self.image,
            release_tuple: self.release_tuple,
            channel: self.channel,
            publication_public_key: self.publication_public_key,
            writer_kill_public_key: self.writer_kill_public_key,
        }
    }
}

impl VerifiedWriterMeasurementFacts {
    #[must_use]
    pub const fn process_start(&self) -> [u8; 32] {
        self.start
    }

    #[must_use]
    pub const fn image(&self) -> [u8; 32] {
        self.image
    }

    #[must_use]
    pub const fn release_tuple(&self) -> [u8; 32] {
        self.release_tuple
    }

    #[must_use]
    pub const fn channel(&self) -> [u8; 32] {
        self.channel
    }

    #[must_use]
    pub const fn publication_public_key(&self) -> [u8; 32] {
        self.publication_public_key
    }

    #[must_use]
    pub const fn writer_kill_public_key(&self) -> [u8; 32] {
        self.writer_kill_public_key
    }
}
