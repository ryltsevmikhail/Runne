//! Linux /dev/fd opens a new description, so validate the original access
//! mode before reopening. Runs while the single-threaded writer exclusively
//! owns the inherited slot; no secret bytes are read during validation.

use std::os::unix::fs::FileTypeExt as _;

use super::CliError;

pub(super) fn validate_original_slot(descriptor: i32) -> Result<(), CliError> {
    let metadata = std::fs::metadata(super::descriptor_path(descriptor))
        .map_err(|_| CliError::CredentialOperation)?;
    if !metadata.file_type().is_fifo() {
        return Err(CliError::CredentialOperation);
    }
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{descriptor}"))
        .map_err(|_| CliError::CredentialOperation)?;
    let flags = info
        .lines()
        .find_map(|line| line.strip_prefix("flags:"))
        .and_then(|value| u32::from_str_radix(value.trim(), 8).ok())
        .ok_or(CliError::CredentialOperation)?;
    if flags & libc::O_ACCMODE as u32 != libc::O_RDONLY as u32 {
        return Err(CliError::CredentialOperation);
    }
    Ok(())
}
