use super::VerifiedInstalledEnrollmentMeasurementFacts;

struct QualificationRuntimeInstalledExpectation {
    candidate_sha256: [u8; 32],
    raw_v3_tuple_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InstalledExpectationError {
    MissingV3,
    SessionMismatch,
    CandidateMismatch,
    RawTupleMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationAdmissionError;

impl VerifiedInstalledEnrollmentMeasurementFacts {
    pub fn verify_qualification_admission(
        &self,
        owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
        verifier: &mut runne_native_qualification::QualificationAdmissionVerifier,
        admission: &runne_native_qualification::PendingQualificationAdmission,
        now_unix_seconds: u64,
    ) -> Result<(), QualificationAdmissionError> {
        let expected = self
            .qualification_runtime_installed_expectation(owned)
            .map_err(|_| QualificationAdmissionError)?;
        verifier
            .verify_exact_borrowed(
                admission,
                expected.candidate_sha256,
                expected.raw_v3_tuple_sha256,
                now_unix_seconds,
            )
            .map_err(|_| QualificationAdmissionError)?;
        Ok(())
    }

    fn qualification_runtime_installed_expectation(
        &self,
        owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    ) -> Result<QualificationRuntimeInstalledExpectation, InstalledExpectationError> {
        #[cfg(feature = "test-support")]
        if let Some((candidate_sha256, raw_v3_tuple_sha256)) = self.qualification_test_expectation {
            let binding = owned.enrollment_binding();
            if self.release != *binding.release_tuple_digest()
                || self.qualification != *binding.qualification_binding_digest()
                || candidate_sha256 == [0; 32]
                || raw_v3_tuple_sha256 == [0; 32]
            {
                return Err(InstalledExpectationError::SessionMismatch);
            }
            return Ok(QualificationRuntimeInstalledExpectation {
                candidate_sha256,
                raw_v3_tuple_sha256,
            });
        }
        let candidate = self
            .qualification_candidate_v3
            .as_ref()
            .ok_or(InstalledExpectationError::MissingV3)?;
        let raw_v3_tuple_sha256 = self
            .raw_v3_tuple
            .ok_or(InstalledExpectationError::MissingV3)?;
        let binding = owned.enrollment_binding();
        let release = *binding.release_tuple_digest();
        let qualification = *binding.qualification_binding_digest();
        if self.release != release
            || self.qualification != qualification
            || candidate.release_binding_digest() != release
            || candidate.qualification_binding_digest() != qualification
        {
            return Err(InstalledExpectationError::SessionMismatch);
        }
        let tuple = candidate.native_enrollment_tuple();
        if tuple.candidate_digest() != self.candidate_source {
            return Err(InstalledExpectationError::CandidateMismatch);
        }
        if tuple.tuple_digest() != raw_v3_tuple_sha256 {
            return Err(InstalledExpectationError::RawTupleMismatch);
        }
        if self.candidate_source == [0; 32] || raw_v3_tuple_sha256 == [0; 32] {
            return Err(InstalledExpectationError::MissingV3);
        }
        Ok(QualificationRuntimeInstalledExpectation {
            candidate_sha256: self.candidate_source,
            raw_v3_tuple_sha256,
        })
    }
}

#[cfg(feature = "test-support")]
impl VerifiedInstalledEnrollmentMeasurementFacts {
    #[doc(hidden)]
    #[must_use]
    pub const fn test_only_qualification_facts(
        release: [u8; 32],
        qualification: [u8; 32],
        candidate: [u8; 32],
        raw_v3_tuple: [u8; 32],
    ) -> Self {
        Self {
            desktop: [1; 32],
            writer: [2; 32],
            daemon: [3; 32],
            credential_service: None,
            runtime_credential_service: None,
            writer_credential_service: None,
            contract: [4; 32],
            desktop_start: [5; 32],
            release,
            raw_v3_tuple: None,
            qualification_candidate_v3: None,
            qualification_test_expectation: Some((candidate, raw_v3_tuple)),
            candidate_source: [6; 32],
            target_manifest: [7; 32],
            qualification,
            installed_generation: 1,
            release_frame: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InstalledExpectationError, VerifiedInstalledEnrollmentMeasurementFacts,
    };
    use crate::tests::updater_enrollment_v3_fixture::{macos_tuple_v3, owned};
    use crate::{NativeEnrollmentQualificationRowV1, NativeEnrollmentTupleAdmission};

    fn v3_admission(candidate: char, service: char) -> NativeEnrollmentTupleAdmission {
        let mut target = crate::tests::updater_enrollment_macos_identity::target();
        target.release_candidate_sha256 = candidate.to_string().repeat(64);
        target.native_enrollment_tuple = None;
        let measured = macos_tuple_v3(&target, service);
        let row = NativeEnrollmentQualificationRowV1::new_v3(
            &target,
            &measured,
            "9".repeat(64),
            99,
            200,
        )
        .unwrap();
        target.native_enrollment_tuple_v3 = Some(
            measured
                .clone()
                .with_qualification(&target, row)
                .unwrap(),
        );
        crate::tests::updater_enrollment_macos_identity::verify_target(&target)
            .unwrap()
            .admit_native_enrollment_v3(&measured)
            .unwrap()
    }

    fn facts(
        admission: &NativeEnrollmentTupleAdmission,
    ) -> VerifiedInstalledEnrollmentMeasurementFacts {
        VerifiedInstalledEnrollmentMeasurementFacts {
            desktop: admission.desktop_sha256,
            writer: admission.writer_sha256,
            daemon: admission.daemon_sha256,
            credential_service: admission.credential_service_sha256,
            runtime_credential_service: admission.runtime_credential_service_configuration().ok(),
            writer_credential_service: admission.writer_credential_service_configuration().ok(),
            contract: [5; 32],
            desktop_start: [6; 32],
            release: admission.release_tuple_sha256,
            raw_v3_tuple: admission.raw_v3_tuple_sha256,
            qualification_candidate_v3: admission.qualification_candidate_v3.clone(),
            #[cfg(feature = "test-support")]
            qualification_test_expectation: None,
            candidate_source: admission.candidate_source_sha256.unwrap(),
            target_manifest: admission.target_manifest_sha256.unwrap(),
            qualification: admission
                .qualification
                .retained_qualification_binding_digest()
                .unwrap(),
            installed_generation: admission.installed_generation,
            release_frame: Vec::new(),
        }
    }

    #[test]
    fn two_real_v3_admissions_reject_each_crossed_installed_fact_independently() {
        let first = v3_admission('d', '4');
        let second = v3_admission('f', 'e');
        let exact = facts(&first);
        assert!(
            exact
                .qualification_runtime_installed_expectation(&owned(
                    exact.release,
                    exact.qualification,
                ))
                .is_ok()
        );

        let second_facts = facts(&second);
        let mut crossed_candidate = facts(&first);
        crossed_candidate.candidate_source = second_facts.candidate_source;
        assert_eq!(
            crossed_candidate
                .qualification_runtime_installed_expectation(&owned(
                    crossed_candidate.release,
                    crossed_candidate.qualification,
                ))
                .err(),
            Some(InstalledExpectationError::CandidateMismatch),
        );

        let mut crossed_raw = facts(&first);
        crossed_raw.raw_v3_tuple = second_facts.raw_v3_tuple;
        assert_eq!(
            crossed_raw
                .qualification_runtime_installed_expectation(&owned(
                    crossed_raw.release,
                    crossed_raw.qualification,
                ))
                .err(),
            Some(InstalledExpectationError::RawTupleMismatch),
        );
        assert_eq!(
            facts(&first)
                .qualification_runtime_installed_expectation(&owned(
                    second_facts.release,
                    second_facts.qualification,
                ))
                .err(),
            Some(InstalledExpectationError::SessionMismatch),
        );
    }

    #[test]
    fn real_qualified_v2_admission_cannot_mint_an_expectation() {
        let target = crate::tests::updater_enrollment_qualification::qualified_target(200);
        let verified = crate::tests::updater_enrollment_macos_identity::verify_target(&target)
            .unwrap();
        let admission = verified
            .admit_native_enrollment(
                &crate::tests::updater_enrollment_qualification::artifacts(&target),
            )
            .unwrap();
        let facts = facts(&admission);
        assert_eq!(
            facts
                .qualification_runtime_installed_expectation(&owned(
                    facts.release,
                    facts.qualification,
                ))
                .err(),
            Some(InstalledExpectationError::MissingV3),
        );
    }
}
