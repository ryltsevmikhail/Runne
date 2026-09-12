#![forbid(unsafe_code)]
//! Root-owned, read-only pins for native qualification bootstrap.

use std::fmt;

use runne_api::MacOsCodeIdentityExpectationV1;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "macos")]
mod macos;

pub const PRODUCTION_BOOTSTRAP_POLICY_PATH: &str =
    "/private/etc/gocode/sourcecraft-native-qualification/bootstrap-policy.json";
const SCHEMA_VERSION: &str = "runne/qualification-bootstrap-policy/v1";
const MAX_SAFE_JS_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationBootstrapPolicyError {
    Rejected,
    Unsupported,
}
impl fmt::Display for QualificationBootstrapPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("qualification bootstrap policy unavailable")
    }
}
impl std::error::Error for QualificationBootstrapPolicyError {}

/// Move-only retained policy. Loading pins data; it never verifies a signer.
pub struct RetainedQualificationBootstrapPolicy {
    policy: QualificationBootstrapPolicy,
    #[cfg(target_os = "macos")]
    retained: macos::RetainedPath,
}
impl RetainedQualificationBootstrapPolicy {
    /// # Errors
    ///
    /// Fails closed unless the fixed production file is safely retained and valid.
    pub fn load_current() -> Result<Self, QualificationBootstrapPolicyError> {
        #[cfg(target_os = "macos")]
        return macos::load_production();
        #[cfg(not(target_os = "macos"))]
        Err(QualificationBootstrapPolicyError::Unsupported)
    }
    /// # Errors
    ///
    /// Fails closed if a retained descriptor or fixed path has changed.
    pub fn revalidate(&self) -> Result<(), QualificationBootstrapPolicyError> {
        #[cfg(target_os = "macos")]
        return self.retained.revalidate();
        #[cfg(not(target_os = "macos"))]
        Err(QualificationBootstrapPolicyError::Unsupported)
    }
    #[must_use]
    pub const fn policy(&self) -> &QualificationBootstrapPolicy {
        &self.policy
    }
}

/// Validated pins only; these values never create verified or capability facts.
pub struct QualificationBootstrapPolicy {
    source_revision: [u8; 20],
    workflow_run_id: String,
    candidate_sha256: [u8; 32],
    raw_v3_tuple_sha256: [u8; 32],
    namespace_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
    profile_sha256: [u8; 32],
    package_root: String,
    desktop: ArtifactExpectation,
    runtime: ArtifactExpectation,
    executor: ArtifactExpectation,
    root_consume: ArtifactExpectation,
    login_euid: u32,
    login_audit_session: i32,
    root_audit_session: i32,
    not_before: u64,
    expires_at: u64,
    max_run_duration_seconds: u64,
    context_public_key: [u8; 32],
    context_key_id: [u8; 32],
    fault_public_key: [u8; 32],
    fault_key_id: [u8; 32],
}
macro_rules! getters { ($($name:ident : $type:ty),* $(,)?) => { $(#[must_use] pub const fn $name(&self) -> $type { self.$name })* }; }
impl QualificationBootstrapPolicy {
    getters!(source_revision: [u8; 20], candidate_sha256: [u8; 32], raw_v3_tuple_sha256: [u8; 32], namespace_sha256: [u8; 32], manifest_sha256: [u8; 32], profile_sha256: [u8; 32], login_euid: u32, login_audit_session: i32, root_audit_session: i32, not_before: u64, expires_at: u64, max_run_duration_seconds: u64, context_public_key: [u8; 32], context_key_id: [u8; 32], fault_public_key: [u8; 32], fault_key_id: [u8; 32]);
    #[must_use]
    pub fn workflow_run_id(&self) -> &str {
        &self.workflow_run_id
    }
    #[must_use]
    pub fn package_root(&self) -> &str {
        &self.package_root
    }
    #[must_use]
    pub const fn desktop(&self) -> &ArtifactExpectation {
        &self.desktop
    }
    #[must_use]
    pub const fn runtime(&self) -> &ArtifactExpectation {
        &self.runtime
    }
    #[must_use]
    pub const fn executor(&self) -> &ArtifactExpectation {
        &self.executor
    }
    #[must_use]
    pub const fn root_consume(&self) -> &ArtifactExpectation {
        &self.root_consume
    }
    #[must_use]
    pub const fn valid_at(&self, now: u64) -> bool {
        self.not_before <= now && now < self.expires_at
    }
}
pub struct ArtifactExpectation {
    identity: MacOsCodeIdentityExpectationV1,
    image_sha256: [u8; 32],
}
impl ArtifactExpectation {
    #[must_use]
    pub const fn identity(&self) -> &MacOsCodeIdentityExpectationV1 {
        &self.identity
    }
    #[must_use]
    pub const fn image_sha256(&self) -> [u8; 32] {
        self.image_sha256
    }
    #[must_use]
    pub fn code_requirement(&self) -> String {
        format!(
            "identifier \"{}\" and anchor apple generic and certificate leaf[subject.OU] = \"{}\" and cdhash H\"{}\"",
            self.identity.identifier(),
            self.identity.team_identifier(),
            self.identity.cdhash()
        )
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePolicy {
    schema_version: String,
    source_revision: String,
    workflow_run_id: String,
    candidate_sha256: String,
    raw_v3_tuple_sha256: String,
    namespace_sha256: String,
    manifest_sha256: String,
    profile_sha256: String,
    package_root: String,
    desktop: WireArtifact,
    runtime: WireArtifact,
    executor: WireArtifact,
    root_consume: WireArtifact,
    login_euid: u32,
    login_audit_session: i32,
    root_audit_session: i32,
    not_before: u64,
    expires_at: u64,
    max_run_duration_seconds: u64,
    context_public_key: String,
    context_key_id: String,
    fault_public_key: String,
    fault_key_id: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WireArtifact {
    identifier: String,
    team_identifier: String,
    cdhash: String,
    image_sha256: String,
}

fn decode(bytes: &[u8]) -> Result<QualificationBootstrapPolicy, QualificationBootstrapPolicyError> {
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
fn hex_value<const N: usize>(value: &str) -> Result<[u8; N], QualificationBootstrapPolicyError> {
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

#[cfg(test)]
mod tests;
