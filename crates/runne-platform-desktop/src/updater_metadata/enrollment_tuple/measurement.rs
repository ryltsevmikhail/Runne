#![cfg_attr(not(all(target_os = "macos", target_arch = "aarch64")), allow(dead_code))]
use std::fs::{File, Metadata};
#[cfg(test)]
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
#[cfg(test)]
use std::path::Path;

use sha2::{Digest, Sha256};

use super::NativeEnrollmentTupleError;

const MAX_NATIVE_ROLE_BYTES: u64 = 64 * 1024 * 1024;

/// Independently measured installed artifacts, not caller-supplied digests.
#[derive(Debug, Eq, PartialEq)]
#[expect(
    clippy::struct_field_names,
    reason = "measured artifact fields make their digest algorithm explicit"
)]
pub struct MeasuredNativeEnrollmentArtifactsV1 {
    pub(super) desktop_sha256: String,
    pub(super) writer_sha256: String,
    pub(super) daemon_sha256: String,
    pub(super) contract_sha256: String,
}

impl MeasuredNativeEnrollmentArtifactsV1 {
    pub(super) fn daemon_and_contract_digests(&self) -> (&str, &str) {
        (&self.daemon_sha256, &self.contract_sha256)
    }

    #[cfg_attr(test, allow(dead_code))]
    pub(super) fn measure(
        desktop: &OpenedNativeEnrollmentFile,
        writer: &OpenedNativeEnrollmentFile,
        daemon: &OpenedNativeEnrollmentFile,
        contract: &OpenedNativeEnrollmentFile,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let desktop_sha256 = desktop.measure()?;
        let writer_sha256 = writer.measure()?;
        let daemon_sha256 = daemon.measure()?;
        let contract_sha256 = contract.measure()?;
        let values = [
            desktop_sha256.as_str(),
            writer_sha256.as_str(),
            daemon_sha256.as_str(),
            contract_sha256.as_str(),
        ];
        (!values.iter().enumerate().any(|(index, value)| values[..index].contains(value)))
            .then_some(Self {
                desktop_sha256,
                writer_sha256,
                daemon_sha256,
                contract_sha256,
            })
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }

    #[cfg(test)]
    pub fn new(
        desktop_sha256: String,
        writer_sha256: String,
        daemon_sha256: String,
        contract_sha256: String,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let values = [
            desktop_sha256.as_str(),
            writer_sha256.as_str(),
            daemon_sha256.as_str(),
            contract_sha256.as_str(),
        ];
        (values.iter().all(|value| valid_digest(value))
            && !values
                .iter()
                .enumerate()
                .any(|(index, value)| values[..index].contains(value)))
        .then_some(Self {
            desktop_sha256,
            writer_sha256,
            daemon_sha256,
            contract_sha256,
        })
        .ok_or(NativeEnrollmentTupleError::Rejected)
    }
}

/// File and identity retained from descriptor-relative package resolution.
#[derive(Debug)]
pub(super) struct OpenedNativeEnrollmentFile {
    file: File,
    metadata: Metadata,
}

impl OpenedNativeEnrollmentFile {
    pub(super) fn new(file: File) -> Result<Self, NativeEnrollmentTupleError> {
        let metadata = file.metadata().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        valid_regular(&metadata).then_some(Self { file, metadata }).ok_or(NativeEnrollmentTupleError::Rejected)
    }

    pub(super) fn matches_file(&self, file: &File) -> Result<bool, NativeEnrollmentTupleError> {
        Ok(same_identity(&self.metadata, &file.metadata().map_err(|_| NativeEnrollmentTupleError::Rejected)?)
            && same_security(&self.metadata, &file.metadata().map_err(|_| NativeEnrollmentTupleError::Rejected)?))
    }

    pub(super) fn matches_opened(&self, other: &Self) -> Result<bool, NativeEnrollmentTupleError> {
        self.matches_file(&other.file)
    }

    #[cfg(target_os = "macos")]
    pub(super) const fn metadata(&self) -> &Metadata { &self.metadata }

    pub(super) fn measure(&self) -> Result<String, NativeEnrollmentTupleError> {
        let before = self.file.metadata().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !valid_regular(&before) || !same_identity(&self.metadata, &before) || !same_security(&self.metadata, &before) {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let expected_len = before.len();
        let mut file = self.file.try_clone().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        file.seek(SeekFrom::Start(0)).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let mut hasher = Sha256::new();
        let mut chunk = [0_u8; 16 * 1024];
        let mut remaining = expected_len;
        while remaining != 0 {
            let limit = usize::try_from(remaining.min(chunk.len() as u64)).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
            let read = file.read(&mut chunk[..limit]).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
            if read == 0 { return Err(NativeEnrollmentTupleError::Rejected); }
            hasher.update(&chunk[..read]);
            remaining -= read as u64;
        }
        if file.read(&mut [0_u8; 1]).map_err(|_| NativeEnrollmentTupleError::Rejected)? != 0 {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let after = self.file.metadata().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        (valid_regular(&after) && same_identity(&before, &after) && same_security(&before, &after))
            .then(|| hex::encode(hasher.finalize()))
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }
}

#[cfg(test)]
fn open_regular_file(path: &Path) -> Result<File, NativeEnrollmentTupleError> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    };
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(0x0020_0000)
            .open(path)
    };
    #[cfg(not(any(unix, windows)))]
    let file = OpenOptions::new().read(true).open(path);
    let file = file.map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    OpenedNativeEnrollmentFile::new(file).map(|opened| opened.file)
}

fn valid_regular(metadata: &Metadata) -> bool {
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_NATIVE_ROLE_BYTES { return false; }
    #[cfg(unix)]
    if std::os::unix::fs::MetadataExt::nlink(metadata) != 1 || std::os::unix::fs::MetadataExt::mode(metadata) & 0o022 != 0 { return false; }
    #[cfg(windows)]
    if std::os::windows::fs::MetadataExt::file_attributes(metadata) & 0x400 != 0 { return false; }
    true
}

fn same_security(first: &Metadata, second: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        first.uid() == second.uid()
            && first.mode() == second.mode()
            && first.ctime() == second.ctime()
            && first.ctime_nsec() == second.ctime_nsec()
            && first.mtime() == second.mtime()
            && first.mtime_nsec() == second.mtime_nsec()
    }
    #[cfg(not(unix))]
    { first.permissions().readonly() == second.permissions().readonly() }
}

fn same_identity(first: &Metadata, second: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        first.dev() == second.dev()
            && first.ino() == second.ino()
            && first.len() == second.len()
            && first.nlink() == second.nlink()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        first.volume_serial_number() == second.volume_serial_number()
            && first.file_index() == second.file_index()
    }
    #[cfg(not(any(unix, windows)))]
    {
        first.len() == second.len()
    }
}

#[cfg(test)]
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_oversized_native_role() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("role");
        File::create(&path)
            .unwrap()
            .set_len(MAX_NATIVE_ROLE_BYTES + 1)
            .unwrap();
        assert!(open_regular_file(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn identity_mismatch_is_detected() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first");
        let second = directory.path().join("second");
        std::fs::write(&first, b"first").unwrap();
        std::fs::write(&second, b"second").unwrap();
        assert!(!same_identity(
            &std::fs::metadata(first).unwrap(),
            &std::fs::metadata(second).unwrap()
        ));
    }
}
