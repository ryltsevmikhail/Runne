use std::str::FromStr as _;

use security_framework::os::macos::code_signing::{Flags, SecCode, SecRequirement};

use super::super::NativeEnrollmentTupleError;
use super::super::enrollment_measurement::OpenedNativeEnrollmentFile;
use super::VerifiedQualificationBootstrapClientPins;

impl VerifiedQualificationBootstrapClientPins {
    pub(in crate::updater_metadata) fn confirm_root_artifact(
        &self,
        artifact: &crate::updater_metadata::bootstrap_gui_executor::root_artifact::RootBootstrapArtifact,
    ) -> Option<()> {
        self.current().then_some(())?;
        artifact.matches_digest(self.descriptor.root_image_sha256())
    }

    pub(in crate::updater_metadata) fn confirm_current_executor(
        &self,
        executor: &OpenedNativeEnrollmentFile,
    ) -> Result<(), NativeEnrollmentTupleError> {
        if !self.current() {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        executor.confirm_current_executable()?;
        let identity =
            crate::updater_metadata::macos_identity::MacOsCodeIdentityV1::from_expectation(
                self.descriptor.executor_identity(),
            );
        let requirement = SecRequirement::from_str(&identity.requirement())
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        SecCode::for_self(Flags::NONE)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?
            .check_validity(
                Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS,
                &requirement,
            )
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let expected: [u8; 32] = hex::decode(self.descriptor.executor_image_sha256())
            .ok()
            .and_then(|value| value.try_into().ok())
            .ok_or(NativeEnrollmentTupleError::Rejected)?;
        (hex::decode(executor.measure()?).ok().as_deref() == Some(&expected))
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)?;
        executor.confirm_current_executable()
    }
}
