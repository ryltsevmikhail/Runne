use super::{
    MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentQualification, NativeEnrollmentTupleV2,
    UpdateTargetV2, VerifiedSignedNativeEnrollmentTupleV3, VerifiedUpdateV2, macos_identity,
    matches_installed,
};

#[cfg(target_os = "macos")]
#[path = "admission/credential_service.rs"]
mod credential_service;

#[path = "admission/file_measurement.rs"]
mod file_measurement;
use file_measurement::measure_regular_file;

/// Non-serializable installed-package admission minted only by `VerifiedUpdateV2`.
#[derive(Debug, Eq, PartialEq)]
pub struct NativeEnrollmentTupleAdmission {
    pub(super) bootstrap_client_pins: Option<super::VerifiedQualificationBootstrapClientPins>,
    pub(super) installed_generation: u64,
    pub(super) desktop_sha256: [u8; 32],
    pub(super) writer_sha256: [u8; 32],
    pub(super) daemon_sha256: [u8; 32],
    pub(super) credential_service_sha256: Option<[u8; 32]>,
    pub(super) release_tuple_sha256: [u8; 32],
    pub(super) raw_v3_tuple_sha256: Option<[u8; 32]>,
    pub(super) raw_v3_candidate_sha256: Option<[u8; 32]>,
    pub(super) qualification_candidate_v3: Option<runne_api::SignedInstalledReleaseCandidateV3>,
    pub(super) candidate_source_sha256: Option<[u8; 32]>,
    pub(super) target_manifest_sha256: Option<[u8; 32]>,
    pub(super) qualification: NativeEnrollmentQualification,
    pub(super) macos_desktop_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
    pub(super) macos_writer_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
    pub(super) macos_daemon_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
    pub(super) macos_credential_service_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
}

impl VerifiedUpdateV2 {
    #[must_use]
    pub const fn target(&self) -> &UpdateTargetV2 {
        self.signed.target()
    }

    #[must_use]
    pub(crate) const fn metadata(&self) -> &super::UpdateMetadataV2 {
        self.signed.metadata()
    }

    #[must_use]
    pub const fn native_enrollment_tuple(&self) -> Option<&NativeEnrollmentTupleV2> {
        self.signed.target().native_enrollment_tuple.as_ref()
    }

    #[must_use]
    pub const fn native_enrollment_tuple_v3(
        &self,
    ) -> Option<&VerifiedSignedNativeEnrollmentTupleV3> {
        self.signed.native_enrollment_tuple_v3()
    }

    #[must_use]
    pub fn admit_native_enrollment(
        &self,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> Option<NativeEnrollmentTupleAdmission> {
        let tuple = self.signed.native_enrollment_tuple()?;
        let installed_matches = matches_installed(tuple, artifacts);
        if !installed_matches {
            return None;
        }
        let candidate = self.signed.qualified_release_candidate();
        let qualification = NativeEnrollmentQualification::from_candidate(candidate, true);
        let [desktop, writer, daemon] = [
            tuple
                .desktop_code_identity()
                .map(macos_identity::MacOsCodeIdentityV1::from_expectation),
            tuple
                .writer_code_identity()
                .map(macos_identity::MacOsCodeIdentityV1::from_expectation),
            tuple
                .daemon_code_identity()
                .map(macos_identity::MacOsCodeIdentityV1::from_expectation),
        ];
        Some(NativeEnrollmentTupleAdmission {
            bootstrap_client_pins: None,
            installed_generation: self.metadata().targets.version,
            desktop_sha256: tuple.desktop_image_digest(),
            writer_sha256: tuple.writer_image_digest(),
            daemon_sha256: tuple.daemon_image_digest(),
            credential_service_sha256: None,
            release_tuple_sha256: candidate.map_or_else(
                || tuple.inner_tuple_digest(),
                runne_api::SignedInstalledReleaseCandidateV2::release_binding_digest,
            ),
            raw_v3_tuple_sha256: None,
            raw_v3_candidate_sha256: None,
            qualification_candidate_v3: None,
            candidate_source_sha256: candidate
                .map(|value| value.native_enrollment_tuple().candidate_digest()),
            target_manifest_sha256: candidate
                .map(runne_api::SignedInstalledReleaseCandidateV2::target_manifest_digest),
            qualification,
            macos_desktop_code_identity: desktop,
            macos_writer_code_identity: writer,
            macos_daemon_code_identity: daemon,
            macos_credential_service_code_identity: None,
        })
    }

    #[must_use]
    pub fn admit_native_enrollment_v3(
        &self,
        measured: &runne_api::NativeEnrollmentTupleV3,
    ) -> Option<NativeEnrollmentTupleAdmission> {
        let tuple = self.signed.native_enrollment_tuple_v3()?;
        let installed_matches = tuple.matches_measured_tuple(measured);
        if !installed_matches {
            return None;
        }
        let candidate = self.signed.qualified_release_candidate_v3();
        Some(NativeEnrollmentTupleAdmission {
            bootstrap_client_pins: None,
            installed_generation: self.metadata().targets.version,
            desktop_sha256: tuple.desktop_digest(),
            writer_sha256: tuple.writer_digest(),
            daemon_sha256: tuple.daemon_digest(),
            credential_service_sha256: Some(tuple.credential_service_digest()),
            release_tuple_sha256: candidate.map_or_else(
                || tuple.tuple_digest(),
                runne_api::SignedInstalledReleaseCandidateV3::release_binding_digest,
            ),
            raw_v3_tuple_sha256: Some(tuple.tuple_digest()),
            raw_v3_candidate_sha256: Some(tuple.candidate_digest()),
            qualification_candidate_v3: candidate.cloned(),
            candidate_source_sha256: candidate
                .map(|value| value.native_enrollment_tuple().candidate_digest()),
            target_manifest_sha256: candidate
                .map(runne_api::SignedInstalledReleaseCandidateV3::target_manifest_digest),
            qualification: NativeEnrollmentQualification::from_candidate_v3(candidate, true),
            macos_desktop_code_identity: Some(
                macos_identity::MacOsCodeIdentityV1::from_expectation(tuple.desktop_identity()),
            ),
            macos_writer_code_identity: Some(
                macos_identity::MacOsCodeIdentityV1::from_expectation(tuple.writer_identity()),
            ),
            macos_daemon_code_identity: Some(
                macos_identity::MacOsCodeIdentityV1::from_expectation(tuple.daemon_identity()),
            ),
            macos_credential_service_code_identity: Some(
                macos_identity::MacOsCodeIdentityV1::from_expectation(
                    tuple.credential_service_identity(),
                ),
            ),
        })
    }

    #[must_use]
    pub fn qualify_native_enrollment(
        &self,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> NativeEnrollmentQualification {
        let installed_matches = self
            .signed
            .native_enrollment_tuple()
            .is_some_and(|tuple| matches_installed(tuple, artifacts));
        NativeEnrollmentQualification::from_candidate(
            self.signed.qualified_release_candidate(),
            installed_matches,
        )
    }
}

#[path = "admission/access.rs"]
mod access;
