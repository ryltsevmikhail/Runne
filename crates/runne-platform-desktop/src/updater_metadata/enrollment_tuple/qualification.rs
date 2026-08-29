/// Platform qualification remains closed until Task 19 validates an exact receipt.
///
/// ```compile_fail
/// use std::path::PathBuf;
/// use runne_platform_desktop::NativeEnrollmentQualification;
///
/// fn tuple_evidence_cannot_launch(
///     qualification: NativeEnrollmentQualification,
///     writer: PathBuf,
/// ) {
///     let _ = qualification.verified_writer(writer);
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NativeEnrollmentQualification {
    Unqualified,
}
