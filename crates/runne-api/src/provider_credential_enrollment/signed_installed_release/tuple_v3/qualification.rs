use super::{
    NativeEnrollmentQualificationRowV1, NativeEnrollmentTupleError, NativeEnrollmentTupleV3,
};
use crate::UpdateTargetV2;

impl NativeEnrollmentTupleV3 {
    pub fn with_qualification(
        mut self,
        target: &UpdateTargetV2,
        qualification: NativeEnrollmentQualificationRowV1,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        qualification
            .valid_binding_v3(target, &self)
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)?;
        self.native_enrollment_qualification = Some(qualification);
        Ok(self)
    }

    pub(in crate::provider_credential_enrollment::signed_installed_release) const fn qualification(
        &self,
    ) -> Option<&NativeEnrollmentQualificationRowV1> {
        self.native_enrollment_qualification.as_ref()
    }

    pub(super) fn qualification_valid(&self, target: &UpdateTargetV2) -> bool {
        self.native_enrollment_qualification
            .as_ref()
            .is_none_or(|row| row.valid_binding_v3(target, self))
    }
}
