use sha2::{Digest, Sha256};

/// Signed bindings for the four native artifacts required by credential
/// enrollment. It is evidence only; absence is deliberately unqualified.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEnrollmentTupleV1 {
    candidate_sha256: String,
    writer_sha256: String,
    daemon_sha256: String,
    contract_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    writer_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    daemon_code_identity: Option<macos_identity::MacOsCodeIdentityV1>,
    tuple_sha256: String,
}

impl NativeEnrollmentTupleV1 {
    /// Builds a self-bound tuple for a target that will be threshold-signed.
    pub fn new(
        candidate_sha256: String,
        writer_sha256: String,
        daemon_sha256: String,
        contract_sha256: String,
        target: &UpdateTargetV2,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let mut tuple = Self {
            candidate_sha256,
            writer_sha256,
            daemon_sha256,
            contract_sha256,
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

    /// Builds a signed tuple that also pins one exact non-ad-hoc macOS code image.
    #[allow(clippy::too_many_arguments)]
    pub fn new_macos(
        candidate_sha256: String,
        writer_sha256: String,
        daemon_sha256: String,
        contract_sha256: String,
        identifier: impl Into<String>,
        team_identifier: impl Into<String>,
        cdhash: impl Into<String>,
        daemon_identifier: impl Into<String>,
        daemon_team_identifier: impl Into<String>,
        daemon_cdhash: impl Into<String>,
        target: &UpdateTargetV2,
    ) -> Result<Self, NativeEnrollmentTupleError> {
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
            candidate_sha256,
            writer_sha256,
            daemon_sha256,
            contract_sha256,
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
            && artifacts.desktop_sha256 == target.artifact_sha256
            && artifacts.writer_sha256 == self.writer_sha256
            && artifacts.daemon_sha256 == self.daemon_sha256
            && artifacts.contract_sha256 == self.contract_sha256
    }

    fn matches_target(&self, target: &UpdateTargetV2) -> bool {
        digests_valid([
            self.candidate_sha256.as_str(),
            self.writer_sha256.as_str(),
            self.daemon_sha256.as_str(),
            self.contract_sha256.as_str(),
            target.artifact_sha256.as_str(),
        ]) && self.candidate_sha256 == target.release_candidate_sha256
            && self.contract_sha256 == target.bundle_sha256
            && match target.platform.as_str() {
                "macos" => self
                    .writer_code_identity
                    .as_ref()
                    .is_some_and(macos_identity::MacOsCodeIdentityV1::valid)
                    && self
                        .daemon_code_identity
                        .as_ref()
                        .is_some_and(macos_identity::MacOsCodeIdentityV1::valid)
                    && self.writer_code_identity != self.daemon_code_identity,
                _ => self.writer_code_identity.is_none() && self.daemon_code_identity.is_none(),
            }
            && all_distinct([
                self.writer_sha256.as_str(),
                self.daemon_sha256.as_str(),
                self.contract_sha256.as_str(),
                target.artifact_sha256.as_str(),
            ])
            && (self.tuple_sha256.is_empty() || self.tuple_sha256 == self.digest_for(target))
    }

    fn digest_for(&self, target: &UpdateTargetV2) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"gocode/native-enrollment-release-tuple/v1\0");
        for value in [
            self.candidate_sha256.as_str(),
            target.product_id.as_str(),
            target.version.as_str(),
            target.platform.as_str(),
            target.arch.as_str(),
            target.profile_id.as_str(),
            target.artifact_sha256.as_str(),
            self.writer_sha256.as_str(),
            self.daemon_sha256.as_str(),
            self.contract_sha256.as_str(),
        ] {
            hasher.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
            hasher.update(value.as_bytes());
        }
        for (role, identity) in [
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

/// Independently measured installed artifacts. This contains no paths or
/// process identity, so callers cannot turn a location into package trust.
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_field_names,
    reason = "measured artifact fields make their digest algorithm explicit"
)]
pub struct MeasuredNativeEnrollmentArtifactsV1 {
    desktop_sha256: String,
    writer_sha256: String,
    daemon_sha256: String,
    contract_sha256: String,
}

impl MeasuredNativeEnrollmentArtifactsV1 {
    pub fn new(
        desktop_sha256: String,
        writer_sha256: String,
        daemon_sha256: String,
        contract_sha256: String,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let values = [
            desktop_sha256.as_str(),
            writer_sha256.as_str(),
            daemon_sha256.as_str(),
            contract_sha256.as_str(),
        ];
        if !digests_valid(values) || !all_distinct(values) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        Ok(Self {
            desktop_sha256,
            writer_sha256,
            daemon_sha256,
            contract_sha256,
        })
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
