#![cfg_attr(not(all(target_os = "macos", target_arch = "aarch64")), allow(dead_code))]
use super::{NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleError};

#[cfg(target_os = "macos")]
use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};
#[cfg(target_os = "macos")]
use std::str::FromStr as _;

impl NativeEnrollmentArtifactPathsV1 {
    /// Resolves only the daemon's own exact installed macOS package layout.
#[cfg_attr(not(target_os = "macos"), allow(clippy::missing_const_for_fn))]
    pub(crate) fn resolve_installed_from_current_daemon(
    ) -> Result<Self, NativeEnrollmentTupleError> {
        #[cfg(target_os = "macos")]
        {
            let executable = std::env::current_exe().map_err(|_| NativeEnrollmentTupleError::Rejected)?;
            let paths = Self::from_macos_package_executable(&executable, "runned", false)?;
            paths.verify_live_daemon()?;
            Ok(paths)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(NativeEnrollmentTupleError::Rejected)
        }
    }
}

#[cfg(target_os = "macos")]
impl NativeEnrollmentArtifactPathsV1 {
    pub(super) fn confirm_current_signed_daemon(
        &self,
        expected_digest: [u8; 32],
        identity: &super::macos_identity::MacOsCodeIdentityV1,
    ) -> Result<(), NativeEnrollmentTupleError> {
        self.verify_live_daemon()?;
        let code = SecCode::for_self(Flags::NONE).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let requirement = SecRequirement::from_str(&identity.requirement())
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        code.check_validity(Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS, &requirement)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        self.confirm_current_daemon(expected_digest)?;
        self.verify_live_daemon()
    }
}
