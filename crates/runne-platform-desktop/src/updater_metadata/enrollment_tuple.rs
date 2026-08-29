use sha2::{Digest, Sha256};

#[path = "enrollment_tuple/measurement.rs"]
mod enrollment_measurement;
pub use enrollment_measurement::MeasuredNativeEnrollmentArtifactsV1;
#[path = "enrollment_tuple/paths.rs"]
mod enrollment_paths;
#[expect(
    clippy::redundant_pub_crate,
    reason = "fixed package-layout resolution is the remaining production integration step"
)]
pub(crate) use enrollment_paths::NativeEnrollmentArtifactPathsV1;
#[path = "enrollment_tuple/live_daemon.rs"]
mod enrollment_live_daemon;
pub use enrollment_live_daemon::{
    ConfirmedInstalledNativeEnrollment, PreparedInstalledNativeEnrollment,
};

/// Signed bindings for the four native artifacts required by credential
/// enrollment. It is evidence only; absence is deliberately unqualified.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEnrollmentTupleV2 {
    schema_version: u32,
    candidate_sha256: String,
    desktop_sha256: String,
    writer_sha256: String,
    daemon_sha256: String,
    contract_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    desktop_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    writer_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    daemon_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
    tuple_sha256: String,
}

impl NativeEnrollmentTupleV2 {
    /// Builds a self-bound tuple for a target that will be threshold-signed.
    pub fn new(
        candidate_sha256: String,
        desktop_sha256: String,
        writer_sha256: String,
        daemon_sha256: String,
        contract_sha256: String,
        target: &UpdateTargetV2,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let mut tuple = Self {
            schema_version: 2,
            candidate_sha256,
            desktop_sha256,
            writer_sha256,
            daemon_sha256,
            contract_sha256,
            desktop_code_identity: None,
            writer_code_identity: None,
            daemon_code_identity: None,
            tuple_sha256: String::new(),
        };
        if !tuple.matches_target(target) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        tuple.tuple_sha256 = tuple.digest_for(target);
        Ok(tuple)
    }

    /// Builds a signed tuple that pins every exact non-ad-hoc macOS native image.
    #[allow(clippy::too_many_arguments)]
    pub fn new_macos(
        candidate_sha256: String,
        desktop_sha256: String,
        writer_sha256: String,
        daemon_sha256: String,
        contract_sha256: String,
        desktop_identifier: impl Into<String>,
        desktop_team_identifier: impl Into<String>,
        desktop_cdhash: impl Into<String>,
        identifier: impl Into<String>,
        team_identifier: impl Into<String>,
        cdhash: impl Into<String>,
        daemon_identifier: impl Into<String>,
        daemon_team_identifier: impl Into<String>,
        daemon_cdhash: impl Into<String>,
        target: &UpdateTargetV2,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let Some(desktop_code_identity) = macos_identity::MacOsCodeIdentityV1::new(
            desktop_identifier,
            desktop_team_identifier,
            desktop_cdhash,
        ) else {
            return Err(NativeEnrollmentTupleError::Rejected);
        };
        let Some(writer_code_identity) = macos_identity::MacOsCodeIdentityV1::new(
            identifier,
            team_identifier,
            cdhash,
        ) else {
            return Err(NativeEnrollmentTupleError::Rejected);
        };
        let Some(daemon_code_identity) = macos_identity::MacOsCodeIdentityV1::new(
            daemon_identifier,
            daemon_team_identifier,
            daemon_cdhash,
        ) else {
            return Err(NativeEnrollmentTupleError::Rejected);
        };
        let mut tuple = Self {
            schema_version: 2,
            candidate_sha256,
            desktop_sha256,
            writer_sha256,
            daemon_sha256,
            contract_sha256,
            desktop_code_identity: Some(desktop_code_identity),
            writer_code_identity: Some(writer_code_identity),
            daemon_code_identity: Some(daemon_code_identity),
            tuple_sha256: String::new(),
        };
        if !tuple.matches_target(target) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        tuple.tuple_sha256 = tuple.digest_for(target);
        Ok(tuple)
    }

    /// Matches signed role bindings to independently measured installed bytes.
    #[must_use]
    pub fn matches_installed(
        &self,
        target: &UpdateTargetV2,
        artifacts: &MeasuredNativeEnrollmentArtifactsV1,
    ) -> bool {
        self.matches_target(target)
            && artifacts.desktop_sha256 == self.desktop_sha256
            && artifacts.writer_sha256 == self.writer_sha256
            && artifacts.daemon_sha256 == self.daemon_sha256
            && artifacts.contract_sha256 == self.contract_sha256
    }

    fn matches_target(&self, target: &UpdateTargetV2) -> bool {
        self.schema_version == 2
            && digests_valid([
            self.candidate_sha256.as_str(),
            self.desktop_sha256.as_str(),
            self.writer_sha256.as_str(),
            self.daemon_sha256.as_str(),
            self.contract_sha256.as_str(),
            target.artifact_sha256.as_str(),
        ]) && self.candidate_sha256 == target.release_candidate_sha256
            && self.contract_sha256 == target.bundle_sha256
            && match target.platform.as_str() {
                "macos" => self
                    .desktop_code_identity
                    .as_ref()
                    .is_some_and(macos_identity::MacOsCodeIdentityV1::valid)
                    && self
                    .writer_code_identity
                    .as_ref()
                    .is_some_and(macos_identity::MacOsCodeIdentityV1::valid)
                    && self
                        .daemon_code_identity
                        .as_ref()
                        .is_some_and(macos_identity::MacOsCodeIdentityV1::valid)
                    && self.desktop_code_identity != self.writer_code_identity
                    && self.desktop_code_identity != self.daemon_code_identity
                    && self.writer_code_identity != self.daemon_code_identity,
                _ => self.desktop_code_identity.is_none()
                    && self.writer_code_identity.is_none()
                    && self.daemon_code_identity.is_none(),
            }
            && all_distinct([
            target.artifact_sha256.as_str(),
            self.writer_sha256.as_str(),
            self.daemon_sha256.as_str(),
            self.contract_sha256.as_str(),
            self.desktop_sha256.as_str(),
            ])
            && (self.tuple_sha256.is_empty() || self.tuple_sha256 == self.digest_for(target))
    }

    fn digest_for(&self, target: &UpdateTargetV2) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"gocode/native-enrollment-release-tuple/v2\0");
        hasher.update(self.schema_version.to_be_bytes());
        for value in [
            self.candidate_sha256.as_str(),
            target.product_id.as_str(),
            target.version.as_str(),
            target.platform.as_str(),
            target.arch.as_str(),
            target.profile_id.as_str(),
            target.artifact_sha256.as_str(),
            self.desktop_sha256.as_str(),
            self.writer_sha256.as_str(),
            self.daemon_sha256.as_str(),
            self.contract_sha256.as_str(),
        ] {
            hasher.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        for (role, identity) in [
            ("desktop", self.desktop_code_identity.as_ref()),
            ("writer", self.writer_code_identity.as_ref()),
            ("daemon", self.daemon_code_identity.as_ref()),
        ] {
            let Some(identity) = identity else { continue };
            hasher.update(5_u32.to_be_bytes());
            hasher.update(b"macos");
            hasher.update(u32::try_from(role.len()).unwrap_or(u32::MAX).to_be_bytes());
            hasher.update(role.as_bytes());
            for value in identity.digest_fields() {
                hasher.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
                hasher.update(value.as_bytes());
            }
        }
        hex::encode(hasher.finalize())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEnrollmentTupleError {
    Rejected,
}

fn digests_valid<'a>(values: impl IntoIterator<Item = &'a str>) -> bool {
    values.into_iter().all(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn all_distinct<'a>(values: impl IntoIterator<Item = &'a str>) -> bool {
    let values: Vec<_> = values.into_iter().collect();
    values
        .iter()
        .enumerate()
        .all(|(index, value)| values[..index].iter().all(|prior| prior != value))
}

#[cfg(test)]
#[test]
fn tuple_schema_version_is_rejected_even_with_a_matching_digest() {
    let target = UpdateTargetV2 {
        product_id: "com.runne.desktop".into(), version: "1.2.3".into(), platform: "linux".into(), arch: "x86_64".into(),
        artifact_sha256: "a".repeat(64), artifact_size: 1, artifact_url: "https://updates.example.test/runne".into(),
        release_candidate_sha256: "d".repeat(64), min_os: "linux".into(), profile_id: "gocode-ui-client/2".into(),
        bundle_sha256: "b".repeat(64), runtime_version: "0.1.0".into(), runtime_digest: "9".repeat(64), channel: "stable".into(),
        published_at_unix_seconds: 1, expires_at_unix_seconds: 2, rollback_floor: "1.0.0".into(), native_enrollment_tuple: None,
    };
    let mut tuple = NativeEnrollmentTupleV2::new(
        target.release_candidate_sha256.clone(), "c".repeat(64), "e".repeat(64),
        "f".repeat(64), target.bundle_sha256.clone(), &target,
    ).unwrap();
    tuple.schema_version = 1;
    tuple.tuple_sha256 = tuple.digest_for(&target);
    assert!(!tuple.matches_target(&target));
}
