//! Bounded reading of the Seatbelt profile supplied by the runtime.

use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::fd::{FromRawFd, RawFd};

use crate::args::MAX_PROFILE_BYTES;

/// Reads and validates one profile from an inherited descriptor.
///
/// # Errors
/// Returns a diagnostic when the descriptor cannot be read, the document is
/// larger than [`MAX_PROFILE_BYTES`], is not UTF-8, contains a NUL byte, or
/// does not declare Seatbelt profile version 1.
pub fn read(fd: RawFd) -> Result<CString, String> {
    // SAFETY: the parent passes ownership of this descriptor to the helper.
    let mut file = unsafe { File::from_raw_fd(fd) };
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_PROFILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read profile: {error}"))?;
    if bytes.len() > MAX_PROFILE_BYTES {
        return Err(format!("profile exceeds {MAX_PROFILE_BYTES} bytes"));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| "profile is not UTF-8".to_string())?;
    if !text.trim_start().starts_with("(version 1)") {
        return Err("profile must start with (version 1)".to_string());
    }
    CString::new(bytes).map_err(|_| "profile contains a NUL byte".to_string())
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};
    use std::os::fd::IntoRawFd;

    use super::*;

    fn profile_file(contents: &[u8]) -> File {
        let mut file = tempfile::tempfile().expect("create a temporary profile");
        file.write_all(contents).expect("write the profile");
        file.rewind().expect("rewind the profile");
        file
    }

    #[test]
    fn accepts_a_versioned_profile() {
        let file = profile_file(b"(version 1)\n(deny default)\n");
        let profile = read(file.into_raw_fd()).expect("valid profile");
        assert_eq!(profile.to_bytes(), b"(version 1)\n(deny default)\n");
    }

    #[test]
    fn rejects_a_profile_without_a_version() {
        let file = profile_file(b"(deny default)\n");
        assert!(read(file.into_raw_fd()).is_err());
    }

    #[test]
    fn rejects_a_profile_with_an_interior_nul() {
        let file = profile_file(b"(version 1)\0\n");
        assert!(read(file.into_raw_fd()).is_err());
    }

    #[test]
    fn rejects_an_oversized_profile() {
        let mut contents = b"(version 1)\n".to_vec();
        contents.resize(MAX_PROFILE_BYTES + 1, b' ');
        let file = profile_file(&contents);
        assert!(read(file.into_raw_fd()).is_err());
    }
}
