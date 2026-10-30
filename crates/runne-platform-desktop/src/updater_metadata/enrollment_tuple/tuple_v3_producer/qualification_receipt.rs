//! Strict macOS local qualification receipt for tuple V3 production.
//!
//! The receipt is operational evidence produced by
//! `scripts/desktop/dev-macos-qualification-receipt.sh` on one exact signed
//! `Runne.app`. It is not third-party attestation and never claims release
//! qualification. It binds the measured tuple inputs, the source commit, and
//! the artifact digest so a stale or reused receipt fails closed.

use std::time::{SystemTime, UNIX_EPOCH};

use runne_api::{NativeEnrollmentTupleError, UpdateTargetV2};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::layout::MeasuredTupleV3Artifacts;
use super::resources::ValidatedTupleV3Resources;

const RECEIPT_SCHEMA_VERSION: u32 = 1;
const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const CHECKS: [&str; 3] = [
    "updater-metadata-tests",
    "codesign-bundle-strict",
    "bundle-component-digests",
];
const CHECK_COMMANDS: [&str; 3] = [
    "cargo test -p runne-platform-desktop --lib updater_metadata",
    "codesign --verify --strict --verbose=2 Runne.app",
    "bundle component sha256 match against the measured tuple inputs",
];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct QualificationReceiptV1 {
    schema_version: u32,
    platform: String,
    architecture: String,
    source_commit: String,
    release_candidate_sha256: String,
    artifact_sha256: String,
    desktop_sha256: String,
    writer_sha256: String,
    daemon_sha256: String,
    credential_service_sha256: String,
    launch_agent_plist_sha256: String,
    entitlements_sha256: String,
    provisioning_sha256: String,
    xpc_protocol_sha256: String,
    contract_sha256: String,
    checks: [String; 3],
    check_commands: [String; 3],
    check_exit_statuses: [i32; 3],
    check_log_sha256: String,
    qualified_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl QualificationReceiptV1 {
    fn valid(
        &self,
        target: &UpdateTargetV2,
        candidate_sha256: &str,
        measured: &MeasuredTupleV3Artifacts,
        qualified_at: u64,
        expires_at: u64,
        now: u64,
    ) -> bool {
        let commit_digest = hex::encode(Sha256::digest(self.source_commit.as_bytes()));
        let components = [
            (self.desktop_sha256.as_str(), measured.desktop.as_str()),
            (self.writer_sha256.as_str(), measured.writer.as_str()),
            (self.daemon_sha256.as_str(), measured.daemon.as_str()),
            (
                self.credential_service_sha256.as_str(),
                measured.credential_service.as_str(),
            ),
            (
                self.launch_agent_plist_sha256.as_str(),
                measured.launch_agent.as_str(),
            ),
            (
                self.entitlements_sha256.as_str(),
                measured.entitlements.as_str(),
            ),
            (
                self.provisioning_sha256.as_str(),
                measured.provisioning.as_str(),
            ),
            (
                self.xpc_protocol_sha256.as_str(),
                measured.xpc_protocol.as_str(),
            ),
            (self.contract_sha256.as_str(), measured.contract.as_str()),
        ];
        self.schema_version == RECEIPT_SCHEMA_VERSION
            && self.platform == "macos"
            && self.architecture == "arm64"
            && target.platform == "macos"
            && candidate_sha256 == target.release_candidate_sha256
            && self.release_candidate_sha256 == target.release_candidate_sha256
            && self.release_candidate_sha256 == commit_digest
            && source_commit_well_formed(&self.source_commit)
            && self.artifact_sha256 == target.artifact_sha256
            && components
                .iter()
                .all(|(receipt, measured)| receipt == measured)
            && self.checks.iter().eq(CHECKS.iter())
            && self.check_commands.iter().eq(CHECK_COMMANDS.iter())
            && self.check_exit_statuses == [0, 0, 0]
            && lowercase_hex(&self.check_log_sha256, 64)
            && self.qualified_at_unix_seconds == qualified_at
            && self.expires_at_unix_seconds == expires_at
            && qualified_at != 0
            && qualified_at <= now
            && now < expires_at
            && expires_at <= target.expires_at_unix_seconds
    }
}

fn source_commit_well_formed(value: &str) -> bool {
    lowercase_hex(value, 40)
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Verifies one receipt against the measured tuple inputs and returns its
/// SHA-256, which the qualification row binds.
pub(in crate::updater_metadata) fn verify(
    bytes: &[u8],
    target: &UpdateTargetV2,
    resources: &ValidatedTupleV3Resources,
    measured: &MeasuredTupleV3Artifacts,
    qualified_at: u64,
    expires_at: u64,
) -> Result<String, NativeEnrollmentTupleError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RECEIPT_BYTES {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    let receipt: QualificationReceiptV1 =
        serde_json::from_slice(bytes).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?
        .as_secs();
    receipt
        .valid(
            target,
            &resources.release_candidate_sha256,
            measured,
            qualified_at,
            expires_at,
            now,
        )
        .then(|| hex::encode(Sha256::digest(bytes)))
        .ok_or(NativeEnrollmentTupleError::Rejected)
}
