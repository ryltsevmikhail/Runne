use runne_domain::DigestEqualityMatcherV1;
use subtle::ConstantTimeEq;

use super::{MacOsCodeIdentityExpectationV1, VerifiedSignedInstalledReleaseV2};

impl VerifiedSignedInstalledReleaseV2 {
    /// Compares the exact signed Desktop artifact digest.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_desktop_digest(&self, candidate: &[u8; 32]) -> bool {
        matches_digest(
            &self
                .signed_candidate
                .native_enrollment_tuple
                .desktop_image_digest,
            candidate,
        )
    }

    /// Compares the exact signed writer artifact digest.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_writer_digest(&self, candidate: &[u8; 32]) -> bool {
        matches_digest(
            &self
                .signed_candidate
                .native_enrollment_tuple
                .writer_image_digest,
            candidate,
        )
    }

    /// Compares the exact signed daemon artifact digest.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_daemon_digest(&self, candidate: &[u8; 32]) -> bool {
        matches_digest(
            &self
                .signed_candidate
                .native_enrollment_tuple
                .daemon_image_digest,
            candidate,
        )
    }

    /// Compares the exact signed package-contract digest.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_contract_digest(&self, candidate: &[u8; 32]) -> bool {
        matches_digest(
            &self
                .signed_candidate
                .native_enrollment_tuple
                .contract_digest,
            candidate,
        )
    }

    /// Compares the exact final signed-release binding.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_release_binding(&self, candidate: &[u8; 32]) -> bool {
        matches_digest(&self.signed_candidate.release_binding_digest, candidate)
    }

    /// Compares all signed Desktop code-identity fields.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_desktop_code_identity(
        &self,
        identifier: &str,
        team_identifier: &str,
        cdhash: &str,
    ) -> bool {
        matches_identity(
            self.signed_candidate
                .native_enrollment_tuple
                .desktop_code_identity
                .as_ref(),
            identifier,
            team_identifier,
            cdhash,
        )
    }

    /// Compares all signed writer code-identity fields.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_writer_code_identity(
        &self,
        identifier: &str,
        team_identifier: &str,
        cdhash: &str,
    ) -> bool {
        matches_identity(
            self.signed_candidate
                .native_enrollment_tuple
                .writer_code_identity
                .as_ref(),
            identifier,
            team_identifier,
            cdhash,
        )
    }

    /// Compares all signed daemon code-identity fields.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_daemon_code_identity(
        &self,
        identifier: &str,
        team_identifier: &str,
        cdhash: &str,
    ) -> bool {
        matches_identity(
            self.signed_candidate
                .native_enrollment_tuple
                .daemon_code_identity
                .as_ref(),
            identifier,
            team_identifier,
            cdhash,
        )
    }

    /// Creates a non-authoritative equality matcher for the final binding.
    #[doc(hidden)]
    #[must_use]
    pub fn release_binding_matcher(&self) -> DigestEqualityMatcherV1 {
        DigestEqualityMatcherV1::from_expected(self.signed_candidate.release_binding_digest)
    }
}

fn matches_digest(expected: &[u8; 32], candidate: &[u8; 32]) -> bool {
    bool::from(expected.ct_eq(candidate))
}

fn matches_identity(
    expected: Option<&MacOsCodeIdentityExpectationV1>,
    identifier: &str,
    team_identifier: &str,
    cdhash: &str,
) -> bool {
    expected.is_some_and(|identity| {
        identity.identifier() == identifier
            && identity.team_identifier() == team_identifier
            && identity.cdhash() == cdhash
    })
}

#[cfg(test)]
mod tests {
    use super::super::{
        MacOsCodeIdentityExpectationV1, SignedInstalledReleaseCandidateV2,
        VerifiedSignedInstalledReleaseV2, VerifiedSignedNativeEnrollmentTupleV2,
    };

    fn identity(identifier: &str, cdhash_byte: char) -> MacOsCodeIdentityExpectationV1 {
        MacOsCodeIdentityExpectationV1::new(
            identifier,
            "RUNNE12345",
            cdhash_byte.to_string().repeat(40),
        )
        .unwrap()
    }

    fn release(
        identities: [Option<MacOsCodeIdentityExpectationV1>; 3],
    ) -> VerifiedSignedInstalledReleaseV2 {
        let [
            desktop_code_identity,
            writer_code_identity,
            daemon_code_identity,
        ] = identities;
        VerifiedSignedInstalledReleaseV2 {
            signed_candidate: SignedInstalledReleaseCandidateV2 {
                native_enrollment_tuple: VerifiedSignedNativeEnrollmentTupleV2 {
                    candidate_digest: [1; 32],
                    inner_tuple_digest: [2; 32],
                    desktop_image_digest: [3; 32],
                    writer_image_digest: [4; 32],
                    daemon_image_digest: [5; 32],
                    contract_digest: [6; 32],
                    desktop_code_identity,
                    writer_code_identity,
                    daemon_code_identity,
                },
                target_manifest_digest: [7; 32],
                release_binding_digest: [8; 32],
                qualification_receipt_digest: [9; 32],
                qualification_binding_digest: [10; 32],
                qualified_at_unix_seconds: 11,
                expires_at_unix_seconds: 12,
            },
        }
    }

    #[test]
    fn missing_code_identity_never_matches() {
        let desktop = identity("com.runne.desktop", '1');
        let writer = identity("com.runne.writer", '2');
        let daemon = identity("com.runne.daemon", '3');

        let missing_desktop = release([None, Some(writer.clone()), Some(daemon.clone())]);
        assert!(!missing_desktop.matches_desktop_code_identity(
            desktop.identifier(),
            desktop.team_identifier(),
            desktop.cdhash(),
        ));
        let missing_writer = release([Some(desktop.clone()), None, Some(daemon.clone())]);
        assert!(!missing_writer.matches_writer_code_identity(
            writer.identifier(),
            writer.team_identifier(),
            writer.cdhash(),
        ));
        let missing_daemon = release([Some(desktop), Some(writer), None]);
        assert!(!missing_daemon.matches_daemon_code_identity(
            daemon.identifier(),
            daemon.team_identifier(),
            daemon.cdhash(),
        ));
    }
}
