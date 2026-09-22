use super::ReceivedWriterProcessMeasurements;

/// Live retained-process facts the daemon itself measured for the admitted
/// writer; the receive seam cross-binds every accepted payload against them.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub struct LinuxWriterLiveFacts {
    /// Fresh `/proc` start identity of the exact admitted writer process.
    pub start_identity: [u8; 32],
    /// Pinned image digest measured for the admitted writer process.
    pub image_digest: [u8; 32],
}

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
    /// Linux cross-bind: the transfer-authenticated evidence is accepted only
    /// when its start/image equal the daemon's live remeasure of the exact
    /// pidfd-retained process, returning the authenticated kill publication
    /// key; any drift, replay, or zero key yields `None`.
    #[must_use]
    pub fn verified_linux_kill_public_key(
        &self,
        live_start: [u8; 32],
        live_image: [u8; 32],
    ) -> Option<[u8; 32]> {
        let kill = self.writer_kill_public_key;
        (self.start == live_start
            && self.start != [0; 32]
            && self.image == live_image
            && kill != [0; 32])
            .then_some(kill)
    }

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
