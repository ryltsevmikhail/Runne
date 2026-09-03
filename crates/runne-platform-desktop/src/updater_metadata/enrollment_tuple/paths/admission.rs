use super::NativeEnrollmentArtifactPathsV1;
use crate::{
    NativeEnrollmentTupleAdmission, NativeEnrollmentTupleError, VerifiedUpdateV2,
};

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
            return Ok(verified.admit_native_enrollment_v3(&measured));
        }
        let measured = self.measure()?;
        self.confirm_current()?;
        Ok(verified.admit_native_enrollment(&measured))
    }
}
