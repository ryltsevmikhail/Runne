//! Exact running image of the authenticated desktop peer.
//!
//! A bundle-signed GUI guest reports its `.app` root through static code
//! identification, while the package layout needs the executable inside that
//! bundle. The kernel knows the running image, so ask it first and keep the
//! static-code path only as a fallback for plain, non-bundled peers.

use std::num::NonZeroU32;
use std::path::PathBuf;

use security_framework::os::macos::code_signing::{Flags, GuestAttributes, SecCode};

use super::NativeEnrollmentTupleError;

/// Resolves the executable image a live peer process is running.
pub(super) fn peer_executable_path(pid: NonZeroU32) -> Result<PathBuf, NativeEnrollmentTupleError> {
    running_image_path(pid).map_or_else(|| static_code_path(pid), Ok)
}

/// Kernel-reported executable image of one live process.
fn running_image_path(pid: NonZeroU32) -> Option<PathBuf> {
    runne_macos_process_identity::executable_path(pid)
}

/// Static-code fallback kept for peers that are not packaged as bundles.
fn static_code_path(pid: NonZeroU32) -> Result<PathBuf, NativeEnrollmentTupleError> {
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid.get().cast_signed());
    SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?
        .path(Flags::NONE)
        .ok()
        .and_then(|path| path.to_path())
        .and_then(|path| std::fs::canonicalize(path).ok())
        .ok_or(NativeEnrollmentTupleError::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_the_running_test_image() {
        let Some(pid) = NonZeroU32::new(std::process::id()) else {
            panic!("the test process has a pid");
        };
        let resolved = peer_executable_path(pid).expect("own executable image");
        let expected =
            std::fs::canonicalize(std::env::current_exe().expect("current test executable"))
                .expect("canonical test executable");
        assert_eq!(resolved, expected);
    }
}
