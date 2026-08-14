//! Concrete, fail-closed adapters for the authority command transport.

use std::path::{Component, Path, PathBuf};

use gocode_project_owner_authority::{GitSubject, PurposeProfileV1};
#[cfg(any(test, target_os = "macos"))]
use sha2::{Digest as _, Sha256};

use super::{
    CliError,
    git::{self, CapturedSubject},
    lifecycle::{AuthorityFiles, AuthorityGitResolver},
};

#[path = "adapter_io.rs"]
mod io;
#[cfg(any(test, target_os = "macos"))]
use io::{create_new, existing_exact};
use io::{is_link_or_reparse, read_bounded};

pub(super) const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct SystemAuthorityGit {
    root: PathBuf,
}

impl SystemAuthorityGit {
    pub(super) fn open() -> Result<Self, CliError> {
        Ok(Self {
            root: git::repository_root()?,
        })
    }
}

impl AuthorityGitResolver for SystemAuthorityGit {
    #[cfg(any(test, target_os = "macos"))]
    fn capture_current(&self, profile: &PurposeProfileV1) -> Result<CapturedSubject, CliError> {
        #[cfg(target_os = "macos")]
        {
            git::capture_current(profile)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = profile;
            Err(CliError::AuthorityGit)
        }
    }

    fn resolve_subject(
        &self,
        subject: &GitSubject,
        profile: &PurposeProfileV1,
    ) -> Result<CapturedSubject, CliError> {
        git::resolve_supplied_current(subject, profile)
    }

    fn repository_root(&self) -> &Path {
        &self.root
    }
}

pub(super) struct SystemAuthorityFiles {
    root: PathBuf,
}

impl SystemAuthorityFiles {
    pub(super) const fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn repository_path(&self, path: &str) -> Result<PathBuf, CliError> {
        let relative = Path::new(path);
        if path.is_empty()
            || !relative
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
        {
            return Err(CliError::AuthorityUnavailable);
        }
        let full = self.root.join(relative);
        // Rust's stable filesystem API has no dirfd-relative component walk. This rejects every
        // observed symlink/reparse component, but does not claim protection against a same-UID
        // adversary atomically replacing an ancestor after this check and before `open`. The
        // authority command therefore remains unsuitable for hostile shared worktrees until a
        // reviewed safe openat-style abstraction is available.
        reject_symlink_components(&self.root, relative)?;
        Ok(full)
    }

    #[cfg(any(test, target_os = "macos"))]
    fn external_path(&self, path: &str, require_exists: bool) -> Result<PathBuf, CliError> {
        let requested = Path::new(path);
        if path.is_empty() || requested.file_name().is_none() {
            return Err(CliError::AuthorityUnavailable);
        }
        let parent = requested.parent().ok_or(CliError::AuthorityUnavailable)?;
        let parent = parent
            .canonicalize()
            .map_err(|_| CliError::AuthorityUnavailable)?;
        if parent.starts_with(&self.root) || !parent.is_dir() {
            return Err(CliError::AuthorityUnavailable);
        }
        let full = parent.join(
            requested
                .file_name()
                .ok_or(CliError::AuthorityUnavailable)?,
        );
        if require_exists && !full.is_file() {
            return Err(CliError::AuthorityUnavailable);
        }
        Ok(full)
    }
}

impl AuthorityFiles for SystemAuthorityFiles {
    fn validate_repo_public_output(&self, path: &str) -> Result<(), CliError> {
        let _ = self.repository_path(path)?;
        Ok(())
    }

    #[cfg(any(test, target_os = "macos"))]
    fn create_new_repo_public(&self, path: &str, bytes: &[u8]) -> Result<(), CliError> {
        create_new(&self.repository_path(path)?, bytes, 0o644)
    }

    #[cfg(any(test, target_os = "macos"))]
    fn create_new_or_exact_repo_public(&self, path: &str, bytes: &[u8]) -> Result<(), CliError> {
        let path = self.repository_path(path)?;
        match create_new(&path, bytes, 0o644) {
            Ok(()) => Ok(()),
            Err(_) if existing_exact(&path, bytes, 0o644)? => Ok(()),
            Err(_) => Err(CliError::AuthorityArtifactExists),
        }
    }

    fn read_repo_public(&self, path: &str) -> Result<Vec<u8>, CliError> {
        read_bounded(&self.repository_path(path)?)
    }

    #[cfg(any(test, target_os = "macos"))]
    fn bounded_nofollow_read(&self, path: &str) -> Result<Vec<u8>, CliError> {
        let path = match self.repository_path(path) {
            Ok(path) => path,
            Err(_) => self.external_path(path, true)?,
        };
        read_bounded(&path)
    }

    #[cfg(any(test, target_os = "macos"))]
    fn validate_external_path(
        &self,
        path: &str,
        repository_root: &Path,
    ) -> Result<String, CliError> {
        if repository_root != self.root {
            return Err(CliError::AuthorityUnavailable);
        }
        let external = self.external_path(path, false)?;
        Ok(hex(&Sha256::digest(
            external.as_os_str().as_encoded_bytes(),
        )
        .into()))
    }

    #[cfg(any(test, target_os = "macos"))]
    fn create_new_external_0600(&self, path: &str, bytes: &[u8]) -> Result<(), CliError> {
        create_new(&self.external_path(path, false)?, bytes, 0o600)
    }
}

fn reject_symlink_components(root: &Path, path: &Path) -> Result<(), CliError> {
    let mut current = root.to_path_buf();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(CliError::AuthorityUnavailable);
        };
        current.push(component);
        if current.exists() && is_link_or_reparse(&current)? {
            return Err(CliError::AuthorityUnavailable);
        }
    }
    Ok(())
}

#[cfg(any(test, target_os = "macos"))]
fn hex(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

#[cfg(all(test, unix))]
#[path = "adapter_tests.rs"]
mod adapter_tests;
