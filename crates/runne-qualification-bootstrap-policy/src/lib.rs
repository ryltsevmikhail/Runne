#![forbid(unsafe_code)]
//! Root-owned, read-only pins for native qualification bootstrap.
use runne_api::MacOsCodeIdentityExpectationV1;
use std::fmt;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(test, target_os = "macos"))]
pub(crate) mod wire;
#[cfg(any(test, target_os = "macos"))]
pub(crate) use wire::decode;
#[cfg(test)]
pub(crate) use wire::{SCHEMA_VERSION, WirePolicy};
pub const PRODUCTION_BOOTSTRAP_POLICY_PATH: &str =
    "/private/etc/gocode/sourcecraft-native-qualification/bootstrap-policy.json";
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
    #[cfg_attr(
        not(target_os = "macos"),
        expect(
            clippy::missing_const_for_fn,
            reason = "preserve the macOS I/O API on unsupported targets"
        )
    )]
    pub fn load_current() -> Result<Self, QualificationBootstrapPolicyError> {
        #[cfg(target_os = "macos")]
        return macos::load_production();
        #[cfg(not(target_os = "macos"))]
        Err(QualificationBootstrapPolicyError::Unsupported)
    }
    /// # Errors
    ///
    /// Fails closed if a retained descriptor or fixed path has changed.
    #[cfg_attr(
        not(target_os = "macos"),
        expect(
            clippy::missing_const_for_fn,
            reason = "preserve the macOS I/O API on unsupported targets"
        )
    )]
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
#[cfg(test)]
mod tests;
