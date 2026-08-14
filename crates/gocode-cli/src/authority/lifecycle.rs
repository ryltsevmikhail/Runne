//! Injectable authority lifecycle orchestration.

use std::path::Path;

use super::{CliError, git::CapturedSubject};

#[cfg(any(test, target_os = "macos"))]
#[path = "lifecycle/backup.rs"]
mod backup;
#[cfg(any(test, target_os = "macos"))]
#[path = "lifecycle/init.rs"]
mod init;
#[cfg(any(test, target_os = "macos"))]
#[path = "lifecycle/output_set.rs"]
mod output_set;
#[cfg(any(test, target_os = "macos"))]
#[path = "lifecycle/reset.rs"]
mod reset;
#[cfg(any(test, target_os = "macos"))]
#[path = "lifecycle/restore.rs"]
mod restore;
#[cfg(any(test, target_os = "macos"))]
#[path = "lifecycle/rotate.rs"]
mod rotate;
#[cfg(any(test, target_os = "macos"))]
#[path = "lifecycle/sign.rs"]
mod sign;
#[path = "lifecycle/verify.rs"]
mod verify;

pub(super) trait AuthorityGitResolver {
    #[cfg(any(test, target_os = "macos"))]
    fn capture_current(
        &self,
        profile: &gocode_project_owner_authority::PurposeProfileV1,
    ) -> Result<CapturedSubject, CliError>;
    fn resolve_subject(
        &self,
        subject: &gocode_project_owner_authority::GitSubject,
        profile: &gocode_project_owner_authority::PurposeProfileV1,
    ) -> Result<CapturedSubject, CliError>;
    fn repository_root(&self) -> &Path;
}

impl AuthorityGitResolver for () {
    #[cfg(any(test, target_os = "macos"))]
    fn capture_current(
        &self,
        _: &gocode_project_owner_authority::PurposeProfileV1,
    ) -> Result<CapturedSubject, CliError> {
        Err(CliError::AuthorityUnavailable)
    }
    fn resolve_subject(
        &self,
        _: &gocode_project_owner_authority::GitSubject,
        _: &gocode_project_owner_authority::PurposeProfileV1,
    ) -> Result<CapturedSubject, CliError> {
        Err(CliError::AuthorityUnavailable)
    }
    fn repository_root(&self) -> &Path {
        Path::new(".")
    }
}

pub(super) trait AuthorityTty {
    #[cfg(any(test, target_os = "macos"))]
    fn confirm(&self, display: &str, challenge: &str) -> Result<(), CliError>;
    /// Read bounded hidden terminal input; the returned buffer is zeroized on drop.
    #[cfg(any(test, target_os = "macos"))]
    fn read_hidden(&self, _: &str) -> Result<zeroize::Zeroizing<Vec<u8>>, CliError> {
        Err(CliError::AuthorityUnavailable)
    }
}
pub(super) trait AuthorityRng {}
pub(super) trait AuthorityClock {
    #[cfg(any(test, target_os = "macos"))]
    fn utc_rfc3339_seconds(&self) -> Result<String, CliError>;
}
pub(super) trait AuthorityFiles {
    /// Validate a repository-relative output before any key-store mutation.
    fn validate_repo_public_output(&self, path: &str) -> Result<(), CliError>;
    #[cfg(any(test, target_os = "macos"))]
    /// Publish exact bytes and mode, returning success after the atomic final-name commit point.
    /// Once committed, fallible cleanup or durability probes must not turn success into failure.
    fn create_new_repo_public(&self, path: &str, bytes: &[u8]) -> Result<(), CliError>;
    /// Publish exact bytes, or accept a byte-identical prior committed attempt.
    #[cfg(any(test, target_os = "macos"))]
    fn create_new_or_exact_repo_public(&self, path: &str, bytes: &[u8]) -> Result<(), CliError>;
    fn read_repo_public(&self, path: &str) -> Result<Vec<u8>, CliError>;
    /// Bounded `O_NOFOLLOW` read for a repository or external authority artifact.
    #[cfg(any(test, target_os = "macos"))]
    fn bounded_nofollow_read(&self, path: &str) -> Result<Vec<u8>, CliError>;
    /// Reject paths in the repository and return the digest of canonical external OS-path bytes.
    #[cfg(any(test, target_os = "macos"))]
    fn validate_external_path(
        &self,
        path: &str,
        repository_root: &Path,
    ) -> Result<String, CliError>;
    /// Create an external recovery artifact with `O_EXCL|O_NOFOLLOW|O_CLOEXEC`, mode 0600, then fsync.
    #[cfg(any(test, target_os = "macos"))]
    /// Publish exact external bytes as mode 0600 with the same commit-point semantics.
    fn create_new_external_0600(&self, path: &str, bytes: &[u8]) -> Result<(), CliError>;
}

#[cfg(any(test, target_os = "macos"))]
pub(super) struct InitRequest {
    pub(super) trust_out: String,
}
#[cfg(any(test, target_os = "macos"))]
pub(super) struct SignRequest {
    pub(super) trust_config: String,
    pub(super) receipt_out: String,
}
pub(super) struct VerifyRequest {
    pub(super) trust_config: String,
    pub(super) receipt: String,
    pub(super) anchor_epoch: u64,
    pub(super) anchor_trust_sha256: [u8; 32],
}
#[cfg(any(test, target_os = "macos"))]
pub(super) struct RotateRequest {
    pub(super) trust_config: String,
    pub(super) rotation_out: String,
    pub(super) successor_trust_out: String,
}
#[cfg(any(test, target_os = "macos"))]
pub(super) struct BackupRequest {
    pub(super) trust_config: String,
    pub(super) output: String,
}
#[cfg(any(test, target_os = "macos"))]
pub(super) struct RestoreRequest {
    pub(super) trust_config: String,
    pub(super) input: String,
    pub(super) replace_active_trust: Option<String>,
    pub(super) replace_active_key_id: Option<[u8; 32]>,
}
#[cfg(any(test, target_os = "macos"))]
pub(super) struct TrustResetRequest {
    pub(super) trust_config: String,
    pub(super) acknowledgement: String,
}
#[cfg(any(test, target_os = "macos"))]
pub(super) struct ArtifactReceipt {
    pub(super) kind: String,
    pub(super) path: String,
    pub(super) sha256: [u8; 32],
}
pub(super) struct CommandOutput {
    pub(super) stdout: Vec<u8>,
    #[cfg(any(test, target_os = "macos"))]
    pub(super) artifacts: Vec<ArtifactReceipt>,
}
pub(super) struct AuthorityCommandRunner<'a, S, G, T, R, C, F> {
    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(dead_code, reason = "mutation state is macOS-only")
    )]
    store: &'a S,
    git: &'a G,
    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(dead_code, reason = "mutation confirmation is macOS-only")
    )]
    tty: &'a T,
    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(dead_code, reason = "key generation is macOS-only")
    )]
    rng: &'a mut R,
    #[cfg_attr(
        not(any(test, target_os = "macos")),
        expect(dead_code, reason = "receipt issuance is macOS-only")
    )]
    clock: &'a C,
    files: &'a F,
}

impl<'a, S, G, T, R, C, F> AuthorityCommandRunner<'a, S, G, T, R, C, F> {
    pub(super) const fn new(
        store: &'a S,
        git: &'a G,
        tty: &'a T,
        rng: &'a mut R,
        clock: &'a C,
        files: &'a F,
    ) -> Self {
        Self {
            store,
            git,
            tty,
            rng,
            clock,
            files,
        }
    }
}

#[cfg(test)]
#[path = "lifecycle_backup_restore_tests.rs"]
mod backup_restore_tests;
#[cfg(test)]
#[path = "lifecycle_core_tests.rs"]
mod core_tests;
#[cfg(test)]
#[path = "lifecycle_reset_tests.rs"]
mod reset_tests;
#[cfg(test)]
#[path = "lifecycle_rotate_review_tests.rs"]
mod rotate_review_tests;
#[cfg(test)]
#[path = "lifecycle_rotate_tests.rs"]
mod rotate_tests;
#[cfg(test)]
#[path = "lifecycle_sign_tests.rs"]
mod sign_tests;
#[cfg(test)]
#[path = "lifecycle_test_pending.rs"]
mod test_pending;
#[cfg(test)]
#[path = "lifecycle_test_support.rs"]
mod test_support;
#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;
