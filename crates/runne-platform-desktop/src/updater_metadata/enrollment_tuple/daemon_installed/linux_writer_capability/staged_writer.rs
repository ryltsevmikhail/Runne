use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use runne_platform_ports::provider_credential_broker::VerifiedWriterArtifact;
use runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec;

use super::super::super::NativeEnrollmentTupleError;
use super::{linux_stage, VerifiedInstalledLinuxWriterCapability};

impl VerifiedInstalledLinuxWriterCapability {
    /// Revalidates signed installation evidence before producing the staged writer spec.
    #[must_use]
    pub fn writer_launch_spec(&self, stream: &std::os::unix::net::UnixStream) -> Option<VerifiedWriterLaunchSpec> {
        linux_stage("capability_artifact");
        self.revalidate_for_authenticated_desktop_peer(stream)
            .then_some(())?;
        let installed = self
            .paths
            .verified_linux_writer_artifact(&self.admission)
            .ok()?;
        if installed.image_digest() != self.admission.writer_sha256 {
            return None;
        }
        let writer_length = std::fs::metadata(installed.executable()).ok()?.len();
        let artifact = verified_staged_writer_artifact(
            &self.runtime_root,
            self.admission.writer_sha256,
            writer_length,
            self.admission.release_tuple_sha256,
        )
        .ok()?;
        self.paths
            .confirm_authenticated_peer(&self.peer, stream)
            .ok()?;
        self.revalidate_for_authenticated_desktop_peer(stream)
            .then_some(VerifiedWriterLaunchSpec::new(artifact))
    }
}

const ACTIVATION_DIRECTORY: &str = ".desktop-protected-activation";
const STAGED_DIRECTORY: &str = "executables-v1";

pub(super) fn verified_staged_writer_artifact(
    runtime_root: &Path,
    expected_digest: [u8; 32],
    expected_length: u64,
    release_tuple: [u8; 32],
) -> Result<VerifiedWriterArtifact, NativeEnrollmentTupleError> {
    let stage = staged_directory(runtime_root)?;
    let alias = stage.join("runne");
    let expected = stage.join(format!(
        "{}-{expected_length}.runned",
        hex::encode(expected_digest)
    ));
    let alias_metadata = std::fs::symlink_metadata(&alias)
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if !alias_metadata.file_type().is_symlink()
        || std::fs::canonicalize(&alias).ok().as_deref() != Some(expected.as_path())
        || std::fs::canonicalize(&expected).ok().as_deref() != Some(expected.as_path())
    {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    let (file, identity) = open_staged_writer(&expected, expected_length, expected_digest)?;
    if std::fs::canonicalize(&alias).ok().as_deref() != Some(expected.as_path())
        || !same_file(&file, &expected, &identity)?
    {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    VerifiedWriterArtifact::new(expected, expected_digest, release_tuple)
        .map_err(|_| NativeEnrollmentTupleError::Rejected)
}

fn staged_directory(runtime_root: &Path) -> Result<PathBuf, NativeEnrollmentTupleError> {
    if std::fs::canonicalize(runtime_root).ok().as_deref() != Some(runtime_root) {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    require_private_directory(runtime_root)?;
    let activation = runtime_root.join(ACTIVATION_DIRECTORY);
    require_private_directory(&activation)?;
    let stage = activation.join(STAGED_DIRECTORY);
    require_private_directory(&stage)?;
    Ok(stage)
}

fn require_private_directory(path: &Path) -> Result<(), NativeEnrollmentTupleError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o7777 != 0o700
        || std::fs::canonicalize(path).ok().as_deref() != Some(path)
    {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    Ok(())
}

fn open_staged_writer(
    path: &Path,
    expected_length: u64,
    expected_digest: [u8; 32],
) -> Result<(File, std::fs::Metadata), NativeEnrollmentTupleError> {
    let before = std::fs::symlink_metadata(path)
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.permissions().mode() & 0o7777 != 0o500
        || before.nlink() != 1
        || before.len() != expected_length
    {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let metadata = file
        .metadata()
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if !same_identity(&before, &metadata)
        || !valid_staged_metadata(&metadata, expected_length)
        || !same_identity(&metadata, &std::fs::symlink_metadata(path)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?)
        || hash_file(&file)? != expected_digest
    {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    Ok((file, metadata))
}

fn same_file(
    file: &File,
    path: &Path,
    expected: &std::fs::Metadata,
) -> Result<bool, NativeEnrollmentTupleError> {
    let opened = file
        .metadata()
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let current = std::fs::symlink_metadata(path)
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    Ok(same_identity(expected, &opened)
        && same_identity(expected, &current)
        && valid_staged_metadata(&current, expected.len()))
}

fn valid_staged_metadata(metadata: &std::fs::Metadata, expected_length: u64) -> bool {
    metadata.is_file()
        && metadata.uid() == rustix::process::geteuid().as_raw()
        && metadata.permissions().mode() & 0o7777 == 0o500
        && metadata.nlink() == 1
        && metadata.len() == expected_length
}

fn same_identity(first: &std::fs::Metadata, second: &std::fs::Metadata) -> bool {
    first.dev() == second.dev() && first.ino() == second.ino()
}

fn hash_file(file: &File) -> Result<[u8; 32], NativeEnrollmentTupleError> {
    use sha2::{Digest as _, Sha256};
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut reader = file
        .try_clone()
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if count == 0 {
            return Ok(hash.finalize().into());
        }
        hash.update(&buffer[..count]);
    }
}

#[cfg(test)]
#[path = "staged_writer_tests.rs"]
mod tests;
