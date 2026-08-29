use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::NativeEnrollmentTupleError;

/// Exact native release files measured only by the platform-side coordinator.
#[derive(Debug, Eq, PartialEq)]
pub struct NativeEnrollmentArtifactPathsV1 {
    desktop: PathBuf,
    writer: PathBuf,
    daemon: PathBuf,
    contract: PathBuf,
}

impl NativeEnrollmentArtifactPathsV1 {
    pub fn new(
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

    pub fn measure(&self) -> Result<MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleError> {
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
    let mut file = open_regular_file(path)?;
    let mut hasher = Sha256::new();
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if read == 0 {
            return Ok(hex::encode(hasher.finalize()));
        }
        hasher.update(&chunk[..read]);
    }
}

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
    let metadata = file
        .metadata()
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
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
    Ok(file)
}

#[cfg(test)]
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
