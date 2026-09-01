use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::model::UpdateTargetV2;
use super::qualification::NativeEnrollmentQualificationRowV1;
use super::tuple_identity::MacOsCodeIdentityExpectationV1;

const TUPLE_DOMAIN: &[u8] = b"gocode/native-enrollment-release-tuple/v2\0";

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
    desktop_code_identity: Option<MacOsCodeIdentityExpectationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    writer_code_identity: Option<MacOsCodeIdentityExpectationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    daemon_code_identity: Option<MacOsCodeIdentityExpectationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    native_enrollment_qualification: Option<NativeEnrollmentQualificationRowV1>,
    pub(super) tuple_sha256: String,
}

impl NativeEnrollmentTupleV2 {
    pub fn new(
        candidate_sha256: String,
        desktop_sha256: String,
        writer_sha256: String,
        daemon_sha256: String,
        contract_sha256: String,
        target: &UpdateTargetV2,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        Self::build(
            candidate_sha256,
            desktop_sha256,
            writer_sha256,
            daemon_sha256,
            contract_sha256,
            None,
            target,
        )
    }

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
        let identities = [
            MacOsCodeIdentityExpectationV1::new(
                desktop_identifier,
                desktop_team_identifier,
                desktop_cdhash,
            ),
            MacOsCodeIdentityExpectationV1::new(identifier, team_identifier, cdhash),
            MacOsCodeIdentityExpectationV1::new(
                daemon_identifier,
                daemon_team_identifier,
                daemon_cdhash,
            ),
        ];
        let [Some(desktop), Some(writer), Some(daemon)] = identities else {
            return Err(NativeEnrollmentTupleError::Rejected);
        };
        Self::build(
            candidate_sha256,
            desktop_sha256,
            writer_sha256,
            daemon_sha256,
            contract_sha256,
            Some((desktop, writer, daemon)),
            target,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        candidate_sha256: String,
        desktop_sha256: String,
        writer_sha256: String,
        daemon_sha256: String,
        contract_sha256: String,
        identities: Option<(
            MacOsCodeIdentityExpectationV1,
            MacOsCodeIdentityExpectationV1,
            MacOsCodeIdentityExpectationV1,
        )>,
        target: &UpdateTargetV2,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let (desktop_code_identity, writer_code_identity, daemon_code_identity) = identities
            .map_or((None, None, None), |(desktop, writer, daemon)| {
                (Some(desktop), Some(writer), Some(daemon))
            });
        let mut tuple = Self {
            schema_version: 2,
            candidate_sha256,
            desktop_sha256,
            writer_sha256,
            daemon_sha256,
            contract_sha256,
            desktop_code_identity,
            writer_code_identity,
            daemon_code_identity,
            native_enrollment_qualification: None,
            tuple_sha256: String::new(),
        };
        tuple
            .valid_base(target, false)
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)?;
        tuple.tuple_sha256 = tuple.digest_for(target);
        Ok(tuple)
    }

    pub(super) fn valid_signed(&self, target: &UpdateTargetV2) -> bool {
        self.valid_base(target, true)
            && self
                .native_enrollment_qualification
                .as_ref()
                .is_none_or(|row| row.valid_binding(target, self))
    }

    fn valid_base(&self, target: &UpdateTargetV2, require_digest: bool) -> bool {
        let identities_valid = match target.platform.as_str() {
            "macos" => {
                matches!(target.arch.as_str(), "arm64" | "aarch64")
                    && self
                        .desktop_code_identity
                        .as_ref()
                        .is_some_and(MacOsCodeIdentityExpectationV1::valid)
                    && self
                        .writer_code_identity
                        .as_ref()
                        .is_some_and(MacOsCodeIdentityExpectationV1::valid)
                    && self
                        .daemon_code_identity
                        .as_ref()
                        .is_some_and(MacOsCodeIdentityExpectationV1::valid)
                    && all_distinct([
                        self.desktop_code_identity.as_ref(),
                        self.writer_code_identity.as_ref(),
                        self.daemon_code_identity.as_ref(),
                    ])
            }
            _ => {
                self.desktop_code_identity.is_none()
                    && self.writer_code_identity.is_none()
                    && self.daemon_code_identity.is_none()
            }
        };
        self.schema_version == 2
            && digests_valid([
                self.candidate_sha256.as_str(),
                self.desktop_sha256.as_str(),
                self.writer_sha256.as_str(),
                self.daemon_sha256.as_str(),
                self.contract_sha256.as_str(),
                target.artifact_sha256.as_str(),
                target.bundle_sha256.as_str(),
                target.runtime_digest.as_str(),
            ])
            && self.candidate_sha256 == target.release_candidate_sha256
            && self.contract_sha256 == target.bundle_sha256
            && identities_valid
            && strings_distinct([
                target.artifact_sha256.as_str(),
                self.desktop_sha256.as_str(),
                self.writer_sha256.as_str(),
                self.daemon_sha256.as_str(),
                self.contract_sha256.as_str(),
            ])
            && ((!require_digest && self.tuple_sha256.is_empty())
                || (digest_valid(&self.tuple_sha256)
                    && self.tuple_sha256 == self.digest_for(target)))
    }

    pub(super) fn digest_for(&self, target: &UpdateTargetV2) -> String {
        let mut hasher = Sha256::new();
        hasher.update(TUPLE_DOMAIN);
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
            hash_string(&mut hasher, value);
        }
        for (role, identity) in [
            ("desktop", self.desktop_code_identity.as_ref()),
            ("writer", self.writer_code_identity.as_ref()),
            ("daemon", self.daemon_code_identity.as_ref()),
        ] {
            let Some(identity) = identity else { continue };
            hash_string(&mut hasher, "macos");
            hash_string(&mut hasher, role);
            for value in identity.digest_fields() {
                hash_string(&mut hasher, value);
            }
        }
        hex::encode(hasher.finalize())
    }

    pub(super) fn qualification(&self) -> Option<&NativeEnrollmentQualificationRowV1> {
        self.native_enrollment_qualification.as_ref()
    }
    pub(super) fn tuple_digest(&self) -> Option<[u8; 32]> {
        decode_digest(&self.tuple_sha256)
    }
    pub(super) fn candidate_digest(&self) -> Option<[u8; 32]> {
        decode_digest(&self.candidate_sha256)
    }
    pub(super) fn desktop_digest(&self) -> Option<[u8; 32]> {
        decode_digest(&self.desktop_sha256)
    }
    pub(super) fn writer_digest(&self) -> Option<[u8; 32]> {
        decode_digest(&self.writer_sha256)
    }
    pub(super) fn daemon_digest(&self) -> Option<[u8; 32]> {
        decode_digest(&self.daemon_sha256)
    }
    pub(super) fn contract_digest(&self) -> Option<[u8; 32]> {
        decode_digest(&self.contract_sha256)
    }
    pub(super) fn identities(&self) -> [Option<&MacOsCodeIdentityExpectationV1>; 3] {
        [
            self.desktop_code_identity.as_ref(),
            self.writer_code_identity.as_ref(),
            self.daemon_code_identity.as_ref(),
        ]
    }
    pub(super) fn set_qualification(&mut self, row: NativeEnrollmentQualificationRowV1) {
        self.native_enrollment_qualification = Some(row);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeEnrollmentTupleError {
    Rejected,
}

pub(super) fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
fn digests_valid<'a>(values: impl IntoIterator<Item = &'a str>) -> bool {
    values.into_iter().all(digest_valid)
}
fn strings_distinct<'a>(values: impl IntoIterator<Item = &'a str>) -> bool {
    let values: Vec<_> = values.into_iter().collect();
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}
fn all_distinct<T: PartialEq>(values: impl IntoIterator<Item = T>) -> bool {
    let values: Vec<_> = values.into_iter().collect();
    values
        .iter()
        .enumerate()
        .all(|(index, value)| !values[..index].contains(value))
}
fn hash_string(hasher: &mut Sha256, value: &str) {
    hasher.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    hasher.update(value.as_bytes());
}
pub(super) fn decode_digest(value: &str) -> Option<[u8; 32]> {
    hex::decode(value).ok()?.try_into().ok()
}
