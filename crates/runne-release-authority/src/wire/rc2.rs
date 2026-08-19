use serde::{Deserialize, Serialize};

use super::common::{HexDigest, identifier};
use crate::AuthorityError;

pub(super) use super::rc2_threshold::ThresholdMetadata;

pub(super) const AUTH: &str = "runne.release.rc2-signing-authorization/1";
pub(super) const RECORD_V1: &str = "runne.release.rc2-signed-artifact-record/1";
pub(super) const RECORD: &str = "runne.release.rc2-signed-artifact-record/2";
pub(super) const INVENTORY: &str = "runne.release.signed-envelope-inventory/1";
pub(super) const REPORT: &str = "runne.release.signed-envelope-verification-report/1";
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SigningAuthorization {
    pub schema_version: String,
    pub parent_candidate_sha256: HexDigest,
    pub unsigned_manifest_sha256: HexDigest,
    pub pre_sign_artifacts: Vec<PreSignArtifact>,
    pub signer: OperationalIdentity,
    pub runner: OperationalIdentity,
    pub reviewer: OperationalIdentity,
    pub update_issuer: OperationalIdentity,
    pub workflow_sha256: HexDigest,
    pub effect_namespace: String,
    pub effect_generation: u64,
    pub valid_from: u64,
    pub expires_at: u64,
    pub revocation_epoch: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreSignArtifact {
    pub artifact_slot_id: String,
    pub platform: String,
    pub operation: String,
    pub expected_artifact_sha256: HexDigest,
    pub expected_artifact_length: u64,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OperationalIdentity {
    #[serde(rename = "principal_id")]
    pub principal: String,
    #[serde(rename = "account_id")]
    pub account: String,
    #[serde(rename = "lane_id")]
    pub lane: String,
    #[serde(rename = "key_id")]
    pub key: String,
    #[serde(rename = "signature_profile_id")]
    pub signature_profile: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArtifactRecord {
    pub schema_version: String,
    pub artifact_slot_id: String,
    pub platform: String,
    pub artifact_sha256: HexDigest,
    pub parent_candidate_sha256: HexDigest,
    pub signing_authorization_sha256: HexDigest,
    pub workflow_sha256: HexDigest,
    pub effect_namespace: String,
    pub effect_generation: u64,
    pub operation: String,
    pub pre_sign_artifact_sha256: HexDigest,
    pub pre_sign_artifact_length: u64,
    pub artifact_length: u64,
    pub native_signature_attestation_sha256: HexDigest,
    pub certificate_chain_attestation_sha256: HexDigest,
    pub timestamp_attestation_sha256: HexDigest,
    pub secret_scan_attestation_sha256: HexDigest,
    pub advisory_scan_attestation_sha256: HexDigest,
    pub package_inspection_attestation_sha256: HexDigest,
    pub install_attestation_sha256: HexDigest,
    pub upgrade_attestation_sha256: HexDigest,
    pub rollback_attestation_sha256: HexDigest,
    pub uninstall_attestation_sha256: HexDigest,
    pub signer: OperationalIdentity,
    pub runner: OperationalIdentity,
    pub public_disposition: String,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Inventory {
    pub schema_version: String,
    pub parent_candidate_sha256: HexDigest,
    pub artifact_records: Vec<HexDigest>,
    pub macos_preview_separate: bool,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct VerificationReport {
    pub schema_version: String,
    pub inventory_sha256: HexDigest,
    pub metadata_set_sha256: HexDigest,
    pub linux_verified: bool,
    pub windows_verified: bool,
    pub disposition: String,
    pub linux_native_outcome: String,
    pub windows_native_outcome: String,
}
pub(super) fn auth(value: &SigningAuthorization) -> Result<(), AuthorityError> {
    if value.schema_version != AUTH
        || value.valid_from >= value.expires_at
        || value.revocation_epoch == 0
        || value.effect_generation == 0
        || value.pre_sign_artifacts.len() != 3
        || !matches!(
            value.pre_sign_artifacts.as_slice(),
            [
                PreSignArtifact { artifact_slot_id, platform, operation, .. },
                PreSignArtifact { artifact_slot_id: deb, platform: deb_platform, operation: deb_operation, .. },
                PreSignArtifact { artifact_slot_id: windows, platform: windows_platform, operation: windows_operation, .. },
            ] if artifact_slot_id == "linux-appimage" && platform == "linux" && operation == "native_sign"
                && deb == "linux-deb" && deb_platform == "linux" && deb_operation == "native_sign"
                && windows == "windows-installer-unsigned" && windows_platform == "windows" && windows_operation == "native_sign"
        )
        || !operational_identities_distinct(&[
            &value.signer,
            &value.runner,
            &value.reviewer,
            &value.update_issuer,
        ])
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    identifier(&value.effect_namespace)
}

fn operational_identities_distinct(values: &[&OperationalIdentity]) -> bool {
    dimensions_distinct(values, |value| &value.principal)
        && dimensions_distinct(values, |value| &value.account)
        && dimensions_distinct(values, |value| &value.lane)
        && dimensions_distinct(values, |value| &value.key)
        && dimensions_distinct(values, |value| &value.signature_profile)
}
fn dimensions_distinct<'a>(
    values: &[&'a OperationalIdentity],
    map: impl Fn(&'a OperationalIdentity) -> &'a String,
) -> bool {
    let values = values
        .iter()
        .map(|value| map(value))
        .collect::<std::collections::BTreeSet<_>>();
    values.len() >= 2 && values.into_iter().all(|value| identifier(value).is_ok())
}
pub(super) fn record(value: &ArtifactRecord) -> Result<(), AuthorityError> {
    if value.schema_version != RECORD
        || !matches!(
            (value.artifact_slot_id.as_str(), value.platform.as_str()),
            ("linux-appimage" | "linux-deb", "linux")
                | ("windows-installer-unsigned", "windows")
                | (
                    "macos-app-development-adhoc" | "macos-dmg-development-adhoc",
                    "macos_preview"
                )
        )
        || !matches!(
            value.platform.as_str(),
            "linux" | "windows" | "macos_preview"
        )
        || !matches!(value.public_disposition.as_str(), "public" | "preview_only")
        || (value.platform == "macos_preview") != (value.public_disposition == "preview_only")
        || value.operation != "native_sign"
        || value.effect_generation == 0
    {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    identifier(&value.effect_namespace)?;
    if !operational_identities_distinct(&[&value.signer, &value.runner]) {
        return Err(AuthorityError::NonCanonicalPayload);
    }
    Ok(())
}
pub(super) fn metadata(value: &ThresholdMetadata) -> Result<(), AuthorityError> {
    super::rc2_threshold::metadata(value)
}
pub(super) fn inventory(value: &Inventory) -> Result<(), AuthorityError> {
    (value.schema_version == INVENTORY
        && value.artifact_records.len() == 3
        && value
            .artifact_records
            .windows(2)
            .all(|pair| pair[0] != pair[1])
        && value.macos_preview_separate)
        .then_some(())
        .ok_or(AuthorityError::NonCanonicalPayload)
}
pub(super) fn report(value: &VerificationReport) -> Result<(), AuthorityError> {
    (value.schema_version == REPORT
        && value.linux_verified
        && value.windows_verified
        && value.disposition == "native_verified"
        && value.linux_native_outcome == "verified"
        && value.windows_native_outcome == "verified")
        .then_some(())
        .ok_or(AuthorityError::NonCanonicalPayload)
}
