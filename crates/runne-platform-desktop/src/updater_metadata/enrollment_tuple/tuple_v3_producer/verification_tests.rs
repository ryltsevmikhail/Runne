use std::path::Path;

use runne_api::{MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleError};

use super::{CodeIdentityObserver, CodeIdentityRole, produce_with_observer};
use crate::updater_metadata::enrollment_tuple_v3_producer_tests::Fixture;

struct RejectedBundle;

impl CodeIdentityObserver for RejectedBundle {
    fn verify_bundle(&self, _path: &Path) -> Result<(), NativeEnrollmentTupleError> {
        Err(NativeEnrollmentTupleError::Rejected)
    }

    fn observe(
        &self,
        _role: CodeIdentityRole,
        _path: &Path,
    ) -> Result<MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleError> {
        unreachable!("identity observation must not follow rejected outer bundle")
    }
}

#[test]
fn producer_rejects_outer_bundle_before_trusting_signed_resources() {
    let fixture = Fixture::exact();
    assert_eq!(
        produce_with_observer(&fixture.app, &fixture.target, &RejectedBundle),
        Err(NativeEnrollmentTupleError::Rejected),
    );
}
