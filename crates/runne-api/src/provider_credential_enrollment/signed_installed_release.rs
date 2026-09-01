mod binding;
mod frame;
mod model;
mod qualification;
mod tuple;
mod tuple_identity;
mod verification;

pub use binding::{
    SignedInstalledReleaseCandidateV2, VerifiedSignedInstalledReleaseV2,
    VerifiedSignedNativeEnrollmentTupleV2, VerifiedSignedUpdateMetadataV2,
};
pub use frame::PendingSignedInstalledReleaseMetadataV2;
pub use model::{
    UpdateMetadataSigningError, UpdateMetadataV2, UpdateRootRoleV2, UpdateSignatureV2,
    UpdateSnapshotRoleV2, UpdateTargetV2, UpdateTargetsRoleV2, UpdateTimestampRoleV2,
    UpdateTrustRootV2, update_metadata_signing_bytes,
};
pub use qualification::NativeEnrollmentQualificationRowV1;
pub use tuple::{NativeEnrollmentTupleError, NativeEnrollmentTupleV2};
pub use tuple_identity::MacOsCodeIdentityExpectationV1;
pub use verification::{
    SignedInstalledReleaseVerificationErrorV2, verify_exact_signed_installed_release_v2,
    verify_signed_update_metadata_v2,
};

#[cfg(test)]
mod tests;

/// The exact result is intentionally move-only and non-serializable.
///
/// ```compile_fail
/// use runne_api::VerifiedSignedInstalledReleaseV2;
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<VerifiedSignedInstalledReleaseV2>();
/// ```
///
/// ```compile_fail
/// use runne_api::VerifiedSignedInstalledReleaseV2;
/// fn encode(value: &VerifiedSignedInstalledReleaseV2) {
///     let _ = serde_json::to_vec(value);
/// }
/// ```
///
/// ```compile_fail
/// use runne_api::VerifiedSignedInstalledReleaseV2;
/// let _ = VerifiedSignedInstalledReleaseV2::default();
/// ```
///
/// ```compile_fail
/// use runne_api::VerifiedSignedInstalledReleaseV2;
/// fn inspect(value: &VerifiedSignedInstalledReleaseV2) {
///     let _ = value.signed_candidate();
///     let _ = value.metadata();
///     let _ = value.release_binding_digest();
/// }
/// ```
const _: () = ();
