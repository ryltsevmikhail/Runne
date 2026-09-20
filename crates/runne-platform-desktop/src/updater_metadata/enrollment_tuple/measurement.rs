#![cfg_attr(not(all(target_os = "macos", target_arch = "aarch64")), allow(dead_code))]
use std::fs::{File, Metadata};
use std::io::{Read, Seek, SeekFrom};

use sha2::{Digest, Sha256};

use super::NativeEnrollmentTupleError;

#[cfg(test)]
#[path = "measurement_tests.rs"]
mod measurement_tests;

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

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn test_only_from_digests(
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
    #[cfg(windows)]
    identity: runne_windows_native_handle::RegularFileId,
}

impl OpenedNativeEnrollmentFile {
    pub(super) fn new(file: File) -> Result<Self, NativeEnrollmentTupleError> {
        let metadata = file.metadata().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if !valid_regular(&metadata) { return Err(NativeEnrollmentTupleError::Rejected); }
        #[cfg(windows)]
        let identity = runne_windows_native_handle::identity_of_open_file(&file)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        Ok(Self {
            file,
            metadata,
            #[cfg(windows)]
            identity,
        })
    }

    pub(super) fn matches_file(&self, file: &File) -> Result<bool, NativeEnrollmentTupleError> {
        let other = file.metadata().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        #[cfg(windows)]
        let identity_match = same_identity(&self.identity, file);
        #[cfg(not(windows))]
        let identity_match = same_identity(&self.metadata, &other);
        Ok(identity_match && same_security(&self.metadata, &other))
    }

    pub(super) fn matches_opened(&self, other: &Self) -> Result<bool, NativeEnrollmentTupleError> {
        self.matches_file(&other.file)
    }

    #[cfg(target_os = "macos")]
    pub(super) const fn metadata(&self) -> &Metadata { &self.metadata }

    #[cfg(target_os = "macos")]
    pub(in crate::updater_metadata) fn confirm_current_executable(
        &self,
    ) -> Result<(), NativeEnrollmentTupleError> {
        use std::os::fd::AsFd;

        if !self.matches_file(&self.file)? {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        runne_macos_file_security::require_current_executable_file(self.file.as_fd())
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        self.matches_file(&self.file)?
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }

    pub(super) fn measure(&self) -> Result<String, NativeEnrollmentTupleError> {
        let before = self.file.metadata().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        #[cfg(windows)]
        let identity_stable = same_identity(&self.identity, &self.file);
        #[cfg(not(windows))]
        let identity_stable = same_identity(&self.metadata, &before);
        if !valid_regular(&before) || !identity_stable || !same_security(&self.metadata, &before) {
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
        #[cfg(windows)]
        let identity_held = same_identity(&self.identity, &self.file);
        #[cfg(not(windows))]
        let identity_held = same_identity(&before, &after);
        (valid_regular(&after) && identity_held && same_security(&before, &after))
            .then(|| hex::encode(hasher.finalize()))
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }

    pub(super) fn read_bytes(&self, maximum: u64) -> Result<Vec<u8>, NativeEnrollmentTupleError> {
        let before = self.file.metadata().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        #[cfg(windows)]
        let identity_stable = same_identity(&self.identity, &self.file);
        #[cfg(not(windows))]
        let identity_stable = same_identity(&self.metadata, &before);
        if !valid_regular(&before) || !identity_stable
            || !same_security(&self.metadata, &before) || before.len() > maximum {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let mut file = self.file.try_clone().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        file.seek(SeekFrom::Start(0)).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let capacity = usize::try_from(before.len()).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let mut bytes = Vec::with_capacity(capacity);
        file.read_to_end(&mut bytes).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let after = self.file.metadata().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        #[cfg(windows)]
        let identity_held = same_identity(&self.identity, &self.file);
        #[cfg(not(windows))]
        let identity_held = same_identity(&before, &after);
        (identity_held && same_security(&before, &after))
            .then_some(bytes).ok_or(NativeEnrollmentTupleError::Rejected)
    }
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

#[cfg(unix)]
fn same_identity(first: &Metadata, second: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    first.dev() == second.dev()
        && first.ino() == second.ino()
        && first.len() == second.len()
        && first.nlink() == second.nlink()
}

// std's windows_by_handle metadata accessors are unstable on the pinned stable
// Windows toolchain; the native-handle crate publishes the same FILE_ID_INFO
// identity from an open descriptor and fails closed.
#[cfg(windows)]
fn same_identity(expected: &runne_windows_native_handle::RegularFileId, file: &File) -> bool {
    matches!(runne_windows_native_handle::identity_of_open_file(file), Ok(actual) if actual == *expected)
}

#[cfg(not(any(unix, windows)))]
fn same_identity(first: &Metadata, second: &Metadata) -> bool {
    first.len() == second.len()
}

#[cfg(any(test, feature = "test-support"))]
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
