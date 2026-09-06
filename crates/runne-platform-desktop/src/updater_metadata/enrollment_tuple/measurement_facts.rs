use super::VerifiedDaemonNativeEnrollmentPrepare;

#[cfg(target_os = "macos")]
#[path = "measurement_facts/qualification_admission.rs"]
mod qualification_admission;
#[cfg(target_os = "macos")]
pub use qualification_admission::QualificationAdmissionError;

/// Constructor-sealed installed artifacts and peer facts retained after revalidation.
pub struct VerifiedInstalledEnrollmentMeasurementFacts {
    desktop: [u8; 32],
    writer: [u8; 32],
    daemon: [u8; 32],
    credential_service: Option<[u8; 32]>,
    #[cfg(target_os = "macos")]
    runtime_credential_service: Option<runne_macos_xpc::CredentialServiceEndpointConfiguration>,
    #[cfg(target_os = "macos")]
    writer_credential_service: Option<runne_macos_xpc::CredentialServiceEndpointConfiguration>,
    contract: [u8; 32],
    desktop_start: [u8; 32],
    release: [u8; 32],
    raw_v3_tuple: Option<[u8; 32]>,
    qualification_candidate_v3: Option<runne_api::SignedInstalledReleaseCandidateV3>,
    #[cfg(feature = "test-support")]
    qualification_test_expectation: Option<([u8; 32], [u8; 32])>,
    candidate_source: [u8; 32],
    target_manifest: [u8; 32],
    qualification: [u8; 32],
    installed_generation: u64,
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
        let (metadata, metadata_binding) =
            crate::updater_installed_metadata::InstalledUpdateMetadataJournal::new(
                profile.join("updates/installed-metadata.json"),
            )
            .read()
            .ok()??;
        let record = crate::UpdateJournal::new(profile.join("updates/install-state.json"))
            .read()
            .ok()??;
        if record.state != crate::UpdateInstallState::Committed
            || record.legacy_unbound
            || record.metadata_sha256.as_deref() != Some(metadata_binding.as_str())
            || record.version != metadata.targets.target.version
            || metadata.targets.version != admission.installed_generation
        {
            return None;
        }
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
            credential_service: admission.credential_service_sha256,
            #[cfg(target_os = "macos")]
            runtime_credential_service: admission.runtime_credential_service_configuration().ok(),
            #[cfg(target_os = "macos")]
            writer_credential_service: admission.writer_credential_service_configuration().ok(),
            contract: decode(&measured.contract_sha256)?,
            desktop_start: value.peer.as_ref()?.process_start_digest(),
            release: admission.release_tuple_sha256,
            raw_v3_tuple: admission.raw_v3_tuple_sha256,
            qualification_candidate_v3: admission.qualification_candidate_v3.clone(),
            #[cfg(feature = "test-support")]
            qualification_test_expectation: None,
            candidate_source: admission.candidate_source_sha256?,
            target_manifest: admission.target_manifest_sha256?,
            qualification: admission
                .qualification
                .retained_qualification_binding_digest()?,
            installed_generation: admission.installed_generation,
            release_frame,
        })
    }

    #[must_use]
    pub const fn desktop(&self) -> [u8; 32] {
        self.desktop
    }
    #[must_use]
    pub const fn writer(&self) -> [u8; 32] {
        self.writer
    }
    #[must_use]
    pub const fn daemon(&self) -> [u8; 32] {
        self.daemon
    }
    #[must_use]
    pub const fn credential_service(&self) -> Option<[u8; 32]> {
        self.credential_service
    }
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn runtime_credential_service_configuration(
        &self,
    ) -> Option<runne_macos_xpc::CredentialServiceEndpointConfiguration> {
        self.runtime_credential_service.clone()
    }
    #[cfg(target_os = "macos")]
    #[must_use]
    pub fn writer_credential_service_configuration(
        &self,
    ) -> Option<runne_macos_xpc::CredentialServiceEndpointConfiguration> {
        self.writer_credential_service.clone()
    }
    #[must_use]
    pub const fn contract(&self) -> [u8; 32] {
        self.contract
    }
    #[must_use]
    pub const fn desktop_start(&self) -> [u8; 32] {
        self.desktop_start
    }
    #[must_use]
    pub const fn release(&self) -> [u8; 32] {
        self.release
    }
    #[must_use]
    pub const fn candidate_source(&self) -> [u8; 32] {
        self.candidate_source
    }
    #[must_use]
    pub const fn target_manifest(&self) -> [u8; 32] {
        self.target_manifest
    }
    #[must_use]
    pub const fn qualification(&self) -> [u8; 32] {
        self.qualification
    }
    #[must_use]
    pub const fn installed_generation(&self) -> u64 {
        self.installed_generation
    }

    pub fn write_signed_release_metadata(
        &self,
        writer: &mut impl std::io::Write,
    ) -> std::io::Result<()> {
        writer.write_all(&self.release_frame)
    }
}
