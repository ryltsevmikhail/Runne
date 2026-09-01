use super::VerifiedDaemonNativeEnrollmentPrepare;

/// Constructor-sealed installed artifacts and peer facts retained after revalidation.
pub struct VerifiedInstalledEnrollmentMeasurementFacts {
    desktop: [u8; 32],
    writer: [u8; 32],
    daemon: [u8; 32],
    contract: [u8; 32],
    desktop_start: [u8; 32],
    release: [u8; 32],
    candidate_source: [u8; 32],
    target_manifest: [u8; 32],
    qualification: [u8; 32],
    release_frame: Vec<u8>,
}

impl VerifiedInstalledEnrollmentMeasurementFacts {
    pub(in crate::updater_metadata) fn from_revalidated(
        value: &VerifiedDaemonNativeEnrollmentPrepare,
    ) -> Option<Self> {
        let measured = value.paths.as_ref()?.measure().ok()?;
        let decode = |digest: &str| hex::decode(digest).ok()?.try_into().ok();
        let admission = value.admission.as_ref()?;
        let profile = value.profile_directory.as_ref()?;
        let (metadata, _) = crate::updater_installed_metadata::InstalledUpdateMetadataJournal::new(
            profile.join("updates/installed-metadata.json"),
        )
        .read()
        .ok()??;
        let encoded = serde_json::to_vec(&metadata).ok()?;
        let length = u32::try_from(encoded.len()).ok()?;
        let mut release_frame = Vec::with_capacity(12 + encoded.len());
        release_frame.extend_from_slice(b"GCRMDV2\0");
        release_frame.extend_from_slice(&length.to_be_bytes());
        release_frame.extend_from_slice(&encoded);
        Some(Self {
            desktop: decode(&measured.desktop_sha256)?,
            writer: decode(&measured.writer_sha256)?,
            daemon: decode(&measured.daemon_sha256)?,
            contract: decode(&measured.contract_sha256)?,
            desktop_start: value.peer.as_ref()?.process_start_digest(),
            release: admission.release_tuple_sha256,
            candidate_source: admission.candidate_source_sha256?,
            target_manifest: admission.target_manifest_sha256?,
            qualification: admission.qualification.retained_qualification_binding_digest()?,
            release_frame,
        })
    }

    #[must_use]
    pub const fn desktop(&self) -> [u8; 32] { self.desktop }
    #[must_use]
    pub const fn writer(&self) -> [u8; 32] { self.writer }
    #[must_use]
    pub const fn daemon(&self) -> [u8; 32] { self.daemon }
    #[must_use]
    pub const fn contract(&self) -> [u8; 32] { self.contract }
    #[must_use]
    pub const fn desktop_start(&self) -> [u8; 32] { self.desktop_start }
    #[must_use]
    pub const fn release(&self) -> [u8; 32] { self.release }
    #[must_use]
    pub const fn candidate_source(&self) -> [u8; 32] { self.candidate_source }
    #[must_use]
    pub const fn target_manifest(&self) -> [u8; 32] { self.target_manifest }
    #[must_use]
    pub const fn qualification(&self) -> [u8; 32] { self.qualification }

    pub fn write_signed_release_metadata(
        &self,
        writer: &mut impl std::io::Write,
    ) -> std::io::Result<()> {
        writer.write_all(&self.release_frame)
    }
}
