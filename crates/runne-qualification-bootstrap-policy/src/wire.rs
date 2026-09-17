use runne_api::MacOsCodeIdentityExpectationV1;
use serde::{Deserialize, Serialize};

use super::{ArtifactExpectation, QualificationBootstrapPolicy, QualificationBootstrapPolicyError};

pub const SCHEMA_VERSION: &str = "runne/qualification-bootstrap-policy/v1";
pub const MAX_SAFE_JS_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WirePolicy {
    pub(crate) schema_version: String,
    pub(crate) source_revision: String,
    pub(crate) workflow_run_id: String,
    pub(crate) candidate_sha256: String,
    pub(crate) raw_v3_tuple_sha256: String,
    pub(crate) namespace_sha256: String,
    pub(crate) manifest_sha256: String,
    pub(crate) profile_sha256: String,
    pub(crate) package_root: String,
    pub(crate) desktop: WireArtifact,
    pub(crate) runtime: WireArtifact,
    pub(crate) executor: WireArtifact,
    pub(crate) root_consume: WireArtifact,
    pub(crate) login_euid: u32,
    pub(crate) login_audit_session: i32,
    pub(crate) root_audit_session: i32,
    pub(crate) not_before: u64,
    pub(crate) expires_at: u64,
    pub(crate) max_run_duration_seconds: u64,
    pub(crate) context_public_key: String,
    pub(crate) context_key_id: String,
    pub(crate) fault_public_key: String,
    pub(crate) fault_key_id: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireArtifact {
    pub(crate) identifier: String,
    pub(crate) team_identifier: String,
    pub(crate) cdhash: String,
    pub(crate) image_sha256: String,
}

pub fn decode(
    bytes: &[u8],
) -> Result<QualificationBootstrapPolicy, QualificationBootstrapPolicyError> {
    let wire: WirePolicy =
        serde_json::from_slice(bytes).map_err(|_| QualificationBootstrapPolicyError::Rejected)?;
    if serde_json::to_vec(&wire).ok().as_deref() != Some(bytes)
        || wire.schema_version != SCHEMA_VERSION
    {
        return Err(QualificationBootstrapPolicyError::Rejected);
    }
    let policy = QualificationBootstrapPolicy {
        source_revision: hex_value(&wire.source_revision)?,
        workflow_run_id: wire.workflow_run_id,
        candidate_sha256: hex_value(&wire.candidate_sha256)?,
        raw_v3_tuple_sha256: hex_value(&wire.raw_v3_tuple_sha256)?,
        namespace_sha256: hex_value(&wire.namespace_sha256)?,
        manifest_sha256: hex_value(&wire.manifest_sha256)?,
        profile_sha256: hex_value(&wire.profile_sha256)?,
        package_root: wire.package_root,
        desktop: artifact(wire.desktop)?,
        runtime: artifact(wire.runtime)?,
        executor: artifact(wire.executor)?,
        root_consume: artifact(wire.root_consume)?,
        login_euid: wire.login_euid,
        login_audit_session: wire.login_audit_session,
        root_audit_session: wire.root_audit_session,
        not_before: wire.not_before,
        expires_at: wire.expires_at,
        max_run_duration_seconds: wire.max_run_duration_seconds,
        context_public_key: hex_value(&wire.context_public_key)?,
        context_key_id: hex_value(&wire.context_key_id)?,
        fault_public_key: hex_value(&wire.fault_public_key)?,
        fault_key_id: hex_value(&wire.fault_key_id)?,
    };
    valid(&policy)
        .then_some(policy)
        .ok_or(QualificationBootstrapPolicyError::Rejected)
}

pub fn hex_value<const N: usize>(
    value: &str,
) -> Result<[u8; N], QualificationBootstrapPolicyError> {
    let mut bytes = [0; N];
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err(QualificationBootstrapPolicyError::Rejected);
    }
    hex::decode_to_slice(value, &mut bytes)
        .map_err(|_| QualificationBootstrapPolicyError::Rejected)?;
    (!bytes.iter().all(|b| *b == 0))
        .then_some(bytes)
        .ok_or(QualificationBootstrapPolicyError::Rejected)
}

fn artifact(wire: WireArtifact) -> Result<ArtifactExpectation, QualificationBootstrapPolicyError> {
    let _: [u8; 20] = hex_value(&wire.cdhash)?;
    let identity =
        MacOsCodeIdentityExpectationV1::new(wire.identifier, wire.team_identifier, wire.cdhash)
            .ok_or(QualificationBootstrapPolicyError::Rejected)?;
    Ok(ArtifactExpectation {
        identity,
        image_sha256: hex_value(&wire.image_sha256)?,
    })
}

fn valid(policy: &QualificationBootstrapPolicy) -> bool {
    policy.workflow_run_id.len().clamp(1, 128) == policy.workflow_run_id.len()
        && policy
            .workflow_run_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        && canonical_absolute_path(&policy.package_root)
        && policy.login_euid != 0
        && policy.login_audit_session > 0
        && policy.root_audit_session == 0
        && policy.not_before > 0
        && policy.expires_at > policy.not_before
        && policy.max_run_duration_seconds > 0
        && [
            policy.not_before,
            policy.expires_at,
            policy.max_run_duration_seconds,
        ]
        .into_iter()
        .all(|n| n <= MAX_SAFE_JS_INTEGER)
        && policy.max_run_duration_seconds <= policy.expires_at.saturating_sub(policy.not_before)
        && sha256(&policy.context_public_key) == policy.context_key_id
        && sha256(&policy.fault_public_key) == policy.fault_key_id
        && policy.context_public_key != policy.fault_public_key
        && policy.context_key_id != policy.fault_key_id
        && distinct(
            &policy.desktop,
            &policy.runtime,
            &policy.executor,
            &policy.root_consume,
        )
}

fn canonical_absolute_path(value: &str) -> bool {
    value.len() > 1
        && !value.as_bytes().contains(&0)
        && value.starts_with('/')
        && !value.ends_with('/')
        && value
            .split('/')
            .skip(1)
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn sha256(value: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(value).into()
}

fn distinct(
    a: &ArtifactExpectation,
    b: &ArtifactExpectation,
    c: &ArtifactExpectation,
    d: &ArtifactExpectation,
) -> bool {
    let values = [a.identity(), b.identity(), c.identity(), d.identity()];
    (0..values.len())
        .all(|left| ((left + 1)..values.len()).all(|right| values[left] != values[right]))
}
