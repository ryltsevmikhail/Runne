//! Reject object sources that would make a locally captured object non-local.

use std::path::PathBuf;

use super::super::super::CliError;
use super::{GitCommandRunner, GitObjectResolver};

impl<R: GitCommandRunner> GitObjectResolver<R> {
    pub(super) fn reject_unsafe_object_sources(&self) -> Result<(), CliError> {
        for arguments in [
            vec![
                "config",
                "--name-only",
                "--get-regexp",
                "^(extensions\\.partialclone|remote\\..*\\.promisor)$",
            ],
            vec!["for-each-ref", "--format=%(refname)", "refs/replace/"],
        ] {
            let arguments = arguments.into_iter().map(str::to_owned).collect::<Vec<_>>();
            let output = self.raw_owned(&arguments, &[])?;
            if output.status == 0 && !output.stdout.is_empty() {
                return Err(CliError::AuthorityGit);
            }
        }
        for marker in ["objects/info/alternates", "objects/info/http-alternates"] {
            let marker = self.line(["rev-parse", "--git-path", marker])?;
            if self.root.join(marker).exists() {
                return Err(CliError::AuthorityGit);
            }
        }
        self.reject_promisor_markers()
    }

    fn reject_promisor_markers(&self) -> Result<(), CliError> {
        let common_dir = self.line(["rev-parse", "--git-common-dir"])?;
        let pack_dir = self.line(["rev-parse", "--git-path", "objects/pack"])?;
        let pack_dir = self.root.join(PathBuf::from(pack_dir));
        if !pack_dir.exists() {
            return Ok(());
        }
        let common_dir = self
            .root
            .join(PathBuf::from(common_dir))
            .canonicalize()
            .map_err(|_| CliError::AuthorityGit)?;
        let pack_dir = pack_dir
            .canonicalize()
            .map_err(|_| CliError::AuthorityGit)?;
        if pack_dir != common_dir.join("objects/pack") {
            return Err(CliError::AuthorityGit);
        }
        for entry in pack_dir.read_dir().map_err(|_| CliError::AuthorityGit)? {
            let entry = entry.map_err(|_| CliError::AuthorityGit)?;
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "promisor")
            {
                return Err(CliError::AuthorityGit);
            }
        }
        Ok(())
    }
}
