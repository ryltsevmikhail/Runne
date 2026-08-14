//! Hardened read-only Git object resolver for immutable authority subjects.

use std::path::PathBuf;

use gocode_project_owner_authority::{DocumentBinding, GitSubject, PurposeProfileV1};
use sha2::{Digest as _, Sha256};

use super::super::CliError;

pub(super) const MAX_GIT_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
#[cfg(any(test, target_os = "macos"))]
const HEAD_COMMIT: &str = "HEAD^{commit}";

#[path = "git/system.rs"]
mod system;
#[path = "git/system_config.rs"]
mod system_config;
#[path = "git/validation.rs"]
mod validation;
pub(super) use captured::{CapturedSubject, RetainedDocument};
use system::{GitCommandRunner, GitOutput};
use validation::{hex, oid_width, parse_line, require_oid};

#[cfg(test)]
#[path = "git/negative_tests.rs"]
mod negative_tests;
#[path = "git/safety.rs"]
mod safety;
#[path = "git/subject.rs"]
mod subject;
#[cfg(test)]
#[path = "git/system_integration_tests.rs"]
mod system_integration_tests;
#[cfg(test)]
#[path = "git/system_rejection_tests.rs"]
mod system_rejection_tests;
#[cfg(test)]
#[path = "git/tests.rs"]
mod tests;
#[cfg(target_os = "macos")]
pub(super) fn capture_current(profile: &PurposeProfileV1) -> Result<CapturedSubject, CliError> {
    subject::capture_current(profile)
}
pub(super) fn repository_root() -> Result<PathBuf, CliError> {
    subject::repository_root()
}
pub(super) fn resolve_supplied_current(
    subject: &GitSubject,
    profile: &PurposeProfileV1,
) -> Result<CapturedSubject, CliError> {
    subject::resolve_supplied_current(subject, profile)
}

pub(super) struct GitObjectResolver<R> {
    root: PathBuf,
    runner: R,
}

impl<R: GitCommandRunner> GitObjectResolver<R> {
    #[cfg(test)]
    pub(super) const fn new(root: PathBuf, runner: R) -> Self {
        Self { root, runner }
    }

    fn capture_exact(
        &self,
        object_format: &str,
        commit: String,
        tree: String,
        profile: &PurposeProfileV1,
        width: usize,
    ) -> Result<CapturedSubject, CliError> {
        let mut bindings = Vec::with_capacity(profile.required_paths.len());
        let mut retained_documents = Vec::with_capacity(profile.required_paths.len());
        let mut object_ids = Vec::with_capacity(profile.required_paths.len());
        for path in &profile.required_paths {
            let (mode, oid) = self.exact_blob(&commit, path, width)?;
            object_ids.push(oid.clone());
            bindings.push(DocumentBinding {
                path: path.clone(),
                mode,
                blob_oid: oid,
                content_sha256: String::new(),
                byte_length: 0,
                schema_id: profile.required_schema_ids.get(path).cloned(),
            });
        }
        let bytes = self.read_blobs(&object_ids, width)?;
        for (binding, bytes) in bindings.iter_mut().zip(bytes) {
            let digest: [u8; 32] = Sha256::digest(&bytes).into();
            binding.content_sha256 = hex(&digest);
            binding.byte_length = bytes.len().try_into().map_err(|_| CliError::AuthorityGit)?;
            let retained = RetainedDocument {
                binding: binding.clone(),
                bytes,
                sha256: digest,
            };
            if retained.binding != *binding
                || Sha256::digest(&retained.bytes).as_slice() != retained.sha256
            {
                return Err(CliError::AuthorityGit);
            }
            retained_documents.push(retained);
        }
        Ok(CapturedSubject {
            subject: GitSubject {
                object_format: object_format.into(),
                commit_oid: commit,
                tree_oid: tree,
            },
            bindings,
            retained_documents,
        })
    }

    #[cfg(any(test, target_os = "macos"))]
    fn head(&self) -> Result<String, CliError> {
        self.line(["rev-parse", "--verify", HEAD_COMMIT])
    }

    fn revision(&self, revision: &str) -> Result<String, CliError> {
        let arguments = vec!["rev-parse".into(), "--verify".into(), revision.into()];
        let output = self.call_owned(&arguments, &[])?;
        parse_line(&output.stdout)
    }

    #[cfg(any(test, target_os = "macos"))]
    fn require_clean(&self) -> Result<(), CliError> {
        if self
            .call(
                [
                    "status",
                    "--porcelain=v2",
                    "-z",
                    "--untracked-files=all",
                    "--ignore-submodules=none",
                ],
                &[],
            )?
            .stdout
            .is_empty()
        {
            Ok(())
        } else {
            #[cfg(any(test, target_os = "macos"))]
            {
                Err(CliError::AuthorityDirtyWorktree)
            }
            #[cfg(all(not(test), not(target_os = "macos")))]
            {
                Err(CliError::AuthorityGit)
            }
        }
    }

    fn exact_blob(
        &self,
        commit: &str,
        path: &str,
        width: usize,
    ) -> Result<(String, String), CliError> {
        let arguments = vec![
            "ls-tree".into(),
            "--full-tree".into(),
            "-z".into(),
            commit.into(),
            "--".into(),
            path.into(),
        ];
        let output = self.call_owned(&arguments, &[])?;
        let entry = output
            .stdout
            .strip_suffix(&[0])
            .ok_or(CliError::AuthorityGit)?;
        let line = std::str::from_utf8(entry).map_err(|_| CliError::AuthorityGit)?;
        let (header, actual_path) = line.split_once('\t').ok_or(CliError::AuthorityGit)?;
        if actual_path != path {
            return Err(CliError::AuthorityGit);
        }
        let mut values = header.split(' ');
        let (Some(mode), Some(kind), Some(oid), None) =
            (values.next(), values.next(), values.next(), values.next())
        else {
            return Err(CliError::AuthorityGit);
        };
        if mode != "100644" || kind != "blob" {
            return Err(CliError::AuthorityGit);
        }
        require_oid(oid, width)?;
        Ok((mode.into(), oid.into()))
    }

    fn read_blobs(&self, oids: &[String], width: usize) -> Result<Vec<Vec<u8>>, CliError> {
        let input = oids.join("\n").into_bytes();
        let output = self.call(["cat-file", "--batch"], &input)?;
        let mut remainder = output.stdout.as_slice();
        let mut blobs = Vec::with_capacity(oids.len());
        for oid in oids {
            let header_end = remainder
                .iter()
                .position(|byte| *byte == b'\n')
                .ok_or(CliError::AuthorityGit)?;
            let header = std::str::from_utf8(&remainder[..header_end])
                .map_err(|_| CliError::AuthorityGit)?;
            remainder = &remainder[header_end + 1..];
            let mut fields = header.split(' ');
            let (Some(actual), Some(kind), Some(size), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                return Err(CliError::AuthorityGit);
            };
            if actual != oid || kind != "blob" {
                return Err(CliError::AuthorityGit);
            }
            require_oid(actual, width)?;
            let size = size.parse::<usize>().map_err(|_| CliError::AuthorityGit)?;
            if size > MAX_GIT_OUTPUT_BYTES || remainder.len() < size + 1 || remainder[size] != b'\n'
            {
                return Err(CliError::AuthorityGit);
            }
            blobs.push(remainder[..size].to_vec());
            remainder = &remainder[size + 1..];
        }
        if remainder.is_empty() {
            Ok(blobs)
        } else {
            Err(CliError::AuthorityGit)
        }
    }

    fn line<const N: usize>(&self, arguments: [&str; N]) -> Result<String, CliError> {
        let output = self.call(arguments, &[])?;
        parse_line(&output.stdout)
    }

    fn call<const N: usize>(
        &self,
        arguments: [&str; N],
        input: &[u8],
    ) -> Result<GitOutput, CliError> {
        let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
        self.call_owned(&arguments, input)
    }

    fn call_owned(&self, arguments: &[String], input: &[u8]) -> Result<GitOutput, CliError> {
        let output = self.raw_owned(arguments, input)?;
        if output.status != 0 || output.stdout.len() > MAX_GIT_OUTPUT_BYTES {
            Err(CliError::AuthorityGit)
        } else {
            Ok(output)
        }
    }

    fn raw_owned(&self, arguments: &[String], input: &[u8]) -> Result<GitOutput, CliError> {
        let output = self.runner.run(&self.root, arguments, input)?;
        if output.stdout.len() > MAX_GIT_OUTPUT_BYTES {
            Err(CliError::AuthorityGit)
        } else {
            Ok(output)
        }
    }
}
#[path = "git/captured.rs"]
mod captured;
