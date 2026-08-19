//! Capture current Git state or resolve a supplied immutable subject.

use runne_project_owner_authority::{GitSubject, PurposeProfileV1};
use std::path::PathBuf;

use super::super::super::CliError;
use super::system::SystemGit;
use super::{CapturedSubject, GitCommandRunner, GitObjectResolver, oid_width, require_oid};

#[cfg(target_os = "macos")]
pub(super) fn capture_current(profile: &PurposeProfileV1) -> Result<CapturedSubject, CliError> {
    let resolver = GitObjectResolver {
        root: std::env::current_dir().map_err(|_| CliError::AuthorityGit)?,
        runner: SystemGit,
    };
    let root = PathBuf::from(resolver.line(["rev-parse", "--show-toplevel"])?);
    let root = root.canonicalize().map_err(|_| CliError::AuthorityGit)?;
    let resolver = GitObjectResolver {
        root,
        runner: SystemGit,
    };
    resolver.capture_subject(profile)
}

pub(super) fn resolve_supplied_current(
    subject: &GitSubject,
    profile: &PurposeProfileV1,
) -> Result<CapturedSubject, CliError> {
    let root = std::env::current_dir().map_err(|_| CliError::AuthorityGit)?;
    let resolver = GitObjectResolver {
        root,
        runner: SystemGit,
    };
    let root = PathBuf::from(resolver.line(["rev-parse", "--show-toplevel"])?)
        .canonicalize()
        .map_err(|_| CliError::AuthorityGit)?;
    GitObjectResolver {
        root,
        runner: SystemGit,
    }
    .resolve_subject(subject, profile)
}

pub(super) fn repository_root() -> Result<PathBuf, CliError> {
    let root = std::env::current_dir().map_err(|_| CliError::AuthorityGit)?;
    let resolver = GitObjectResolver {
        root,
        runner: SystemGit,
    };
    PathBuf::from(resolver.line(["rev-parse", "--show-toplevel"])?)
        .canonicalize()
        .map_err(|_| CliError::AuthorityGit)
}

impl<R: GitCommandRunner> GitObjectResolver<R> {
    #[cfg(any(test, target_os = "macos"))]
    pub(super) fn capture_subject(
        &self,
        profile: &PurposeProfileV1,
    ) -> Result<CapturedSubject, CliError> {
        self.capture_subject_with_hook(profile, |_| {})
    }

    #[cfg(any(test, target_os = "macos"))]
    pub(super) fn capture_subject_with_hook<F>(
        &self,
        profile: &PurposeProfileV1,
        hook: F,
    ) -> Result<CapturedSubject, CliError>
    where
        F: FnOnce(&CapturedSubject),
    {
        self.reject_unsafe_object_sources()?;
        let head_before = self.head()?;
        self.require_clean()?;
        let object_format = self.line(["rev-parse", "--show-object-format"])?;
        let width = oid_width(&object_format)?;
        let commit = self.head()?;
        if commit != head_before {
            return Err(CliError::AuthorityGit);
        }
        require_oid(&commit, width)?;
        let tree = self.revision(&format!("{commit}^{{tree}}"))?;
        require_oid(&tree, width)?;
        let captured = self.capture_exact(&object_format, commit, tree, profile, width)?;
        hook(&captured);
        if self.head()? != captured.subject.commit_oid {
            return Err(CliError::AuthorityGit);
        }
        Ok(captured)
    }

    /// Resolve only the supplied immutable subject; never reads `HEAD` or status.
    pub(super) fn resolve_subject(
        &self,
        subject: &GitSubject,
        profile: &PurposeProfileV1,
    ) -> Result<CapturedSubject, CliError> {
        self.reject_unsafe_object_sources()?;
        let width = oid_width(&subject.object_format)?;
        require_oid(&subject.commit_oid, width)?;
        require_oid(&subject.tree_oid, width)?;
        if self.revision(&format!("{}^{{commit}}", subject.commit_oid))? != subject.commit_oid
            || self.revision(&format!("{}^{{tree}}", subject.commit_oid))? != subject.tree_oid
        {
            return Err(CliError::AuthorityGit);
        }
        self.capture_exact(
            &subject.object_format,
            subject.commit_oid.clone(),
            subject.tree_oid.clone(),
            profile,
            width,
        )
    }
}
