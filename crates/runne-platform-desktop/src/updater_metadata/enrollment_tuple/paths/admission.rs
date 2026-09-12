use super::NativeEnrollmentArtifactPathsV1;
use crate::{NativeEnrollmentTupleAdmission, NativeEnrollmentTupleError, VerifiedUpdateV2};

impl NativeEnrollmentArtifactPathsV1 {
    pub(crate) fn admit_verified(
        &self,
        verified: &VerifiedUpdateV2,
    ) -> Result<Option<NativeEnrollmentTupleAdmission>, NativeEnrollmentTupleError> {
        #[cfg(target_os = "macos")]
        if verified.native_enrollment_tuple_v3().is_some() {
            let measured = crate::updater_metadata::enrollment_tuple_v3_producer::
                produce_staged_native_enrollment_tuple_v3(&self.application, verified.target())?;
            self.confirm_current()?;
            let mut admission = verified.admit_native_enrollment_v3(&measured);
            if let Some(value) = admission.as_mut() {
                value.bootstrap_client_pins = crate::updater_metadata::bootstrap_client_pins::
                    mint_after_installed_measurement(verified, value);
            }
            self.confirm_current()?;
            return Ok(admission);
        }
        let measured = self.measure()?;
        self.confirm_current()?;
        Ok(verified.admit_native_enrollment(&measured))
    }
}
