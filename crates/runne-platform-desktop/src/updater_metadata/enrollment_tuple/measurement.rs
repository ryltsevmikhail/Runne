use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::NativeEnrollmentTupleError;

const MAX_NATIVE_ROLE_BYTES: u64 = 64 * 1024 * 1024;

/// Exact native release files measured only by the platform-side coordinator.
#[derive(Debug, Eq, PartialEq)]
#[expect(
    clippy::redundant_pub_crate,
    reason = "fixed package-layout resolution is the remaining production integration step"
)]
pub(crate) struct NativeEnrollmentArtifactPathsV1 {
    desktop: PathBuf,
    writer: PathBuf,
    daemon: PathBuf,
    contract: PathBuf,
}

impl NativeEnrollmentArtifactPathsV1 {
    #[cfg_attr(not(test), expect(
        dead_code,
        reason = "fixed package-layout resolution is the remaining production integration step"
    ))]
    pub(crate) fn new(
        desktop: PathBuf,
        writer: PathBuf,
        daemon: PathBuf,
        contract: PathBuf,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let paths = [&desktop, &writer, &daemon, &contract];
        if paths.iter().any(|path| !path.is_absolute())
            || paths
                .iter()
                .enumerate()
                .any(|(index, path)| paths[..index].contains(path))
        {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        Ok(Self {
            desktop,
            writer,
            daemon,
            contract,
        })
    }

    #[cfg_attr(not(test), expect(
        dead_code,
        reason = "fixed package-layout resolution is the remaining production integration step"
    ))]
    pub(crate) fn measure(
        &self,
    ) -> Result<MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleError> {
        MeasuredNativeEnrollmentArtifactsV1::measure(
            &self.desktop,
            &self.writer,
            &self.daemon,
            &self.contract,
        )
    }
}

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
    #[cfg_attr(not(test), expect(
        dead_code,
        reason = "fixed package-layout resolution is the remaining production integration step"
    ))]
    fn measure(
        desktop: &Path,
        writer: &Path,
        daemon: &Path,
        contract: &Path,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        let desktop_sha256 = measure_regular_file(desktop)?;
        let writer_sha256 = measure_regular_file(writer)?;
        let daemon_sha256 = measure_regular_file(daemon)?;
        let contract_sha256 = measure_regular_file(contract)?;
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

fn measure_regular_file(path: &Path) -> Result<String, NativeEnrollmentTupleError> {
    let (mut file, before) = open_regular_file(path)?;
    let expected_len = before.len();
    let mut hasher = Sha256::new();
    let mut chunk = [0_u8; 16 * 1024];
    let mut remaining = expected_len;
    while remaining != 0 {
        let limit = usize::try_from(remaining.min(chunk.len() as u64))
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let read = file
            .read(&mut chunk[..limit])
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if read == 0 {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        hasher.update(&chunk[..read]);
        remaining -= read as u64;
    }
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?
        != 0
    {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    let after = file
        .metadata()
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let current = std::fs::metadata(path).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    (same_identity(&before, &after)
        && same_identity(&before, &current)
        && after.len() == expected_len
        && current.len() == expected_len)
        .then(|| hex::encode(hasher.finalize()))
        .ok_or(NativeEnrollmentTupleError::Rejected)
}

fn open_regular_file(path: &Path) -> Result<(File, Metadata), NativeEnrollmentTupleError> {
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
    let metadata = file
        .metadata()
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > MAX_NATIVE_ROLE_BYTES {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    #[cfg(unix)]
    if std::os::unix::fs::MetadataExt::nlink(&metadata) != 1 {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    #[cfg(windows)]
    if std::os::windows::fs::MetadataExt::file_attributes(&metadata) & 0x400 != 0 {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    Ok((file, metadata))
}

fn same_identity(first: &Metadata, second: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        first.dev() == second.dev() && first.ino() == second.ino()
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
        assert!(measure_regular_file(&path).is_err());
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
