#[cfg(target_os = "macos")]
use security_framework::os::macos::code_signing::{Flags, GuestAttributes, SecCode, SecRequirement};
#[cfg(target_os = "macos")]
use std::{num::NonZeroU32, str::FromStr as _};

#[cfg(target_os = "macos")]
use super::{NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleError, macos_identity};

#[cfg(target_os = "macos")]
impl NativeEnrollmentArtifactPathsV1 {
    pub(super) fn confirm_current_macos_desktop(
        &self,
        expected_digest: [u8; 32],
        identity: &macos_identity::MacOsCodeIdentityV1,
    ) -> Result<(), NativeEnrollmentTupleError> {
        self.confirm_current()?;
        let code = SecCode::for_self(Flags::NONE).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        check_code(&code, identity)?;
        self.matches_desktop_digest(expected_digest)?;
        self.confirm_current()
    }

    pub(super) fn confirm_peer_macos_desktop(
        &self,
        pid: NonZeroU32,
        expected_digest: [u8; 32],
        identity: &macos_identity::MacOsCodeIdentityV1,
    ) -> Result<(), NativeEnrollmentTupleError> {
        self.confirm_current()?;
        let mut attributes = GuestAttributes::new();
        attributes.set_pid(pid.get().cast_signed());
        let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        check_code(&code, identity)?;
        runne_macos_process_identity::MacOsProcessExecutableIdentity::observe(pid, &self.desktop)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?
            .matches_file(self.desktop_file.metadata())
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)?;
        self.matches_desktop_digest(expected_digest)?;
        self.confirm_current()
    }

    fn matches_desktop_digest(&self, expected: [u8; 32]) -> Result<(), NativeEnrollmentTupleError> {
        (hex::decode(self.desktop_file.measure()?).ok().as_deref() == Some(&expected))
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }
}

#[cfg(target_os = "macos")]
fn check_code(code: &SecCode, identity: &macos_identity::MacOsCodeIdentityV1) -> Result<(), NativeEnrollmentTupleError> {
    let requirement = SecRequirement::from_str(&identity.requirement())
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    code.check_validity(Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS, &requirement)
        .map_err(|_| NativeEnrollmentTupleError::Rejected)
}
