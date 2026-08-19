/// One daemon-authenticated admission and its semantic reconciliation digest.
///
/// This move-only carrier is internal to the protected daemon handoff.
pub(crate) struct IssuedRootAdmission {
    admission: runne_api::IssuedRootHandleAdmission,
    admission_digest: [u8; 32],
}

impl IssuedRootAdmission {
    pub(crate) const fn new(
        admission: runne_api::IssuedRootHandleAdmission,
        admission_digest: [u8; 32],
    ) -> Self {
        Self { admission, admission_digest }
    }

    pub(crate) fn into_parts(self) -> (runne_api::IssuedRootHandleAdmission, [u8; 32]) {
        (self.admission, self.admission_digest)
    }
}
