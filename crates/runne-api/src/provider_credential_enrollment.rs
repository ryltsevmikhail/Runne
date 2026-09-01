//! Protected metadata-only provider credential enrollment contracts.

mod host;
mod signed_installed_release;
mod types;

/// Capability admitted only for an exact qualified ProtectedBundled release tuple.
pub const PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2: &str = "provider.credential-enrollment.v2";

pub use host::{
    ProviderCredentialBaseRequestAuthority, ProviderCredentialBrokerCapturedWriter,
    ProviderCredentialBrokerHandoffContext, ProviderCredentialBrokerHandoffFrame,
    ProviderCredentialBrokerHandoffWitness, ProviderCredentialBrokerKillBindingV1,
    ProviderCredentialBrokerKillRelinquishedProof, ProviderCredentialBrokerTransferAuthority,
    ProviderCredentialBrokerWriterEvidenceWitness, ProviderCredentialEnrollmentHostError,
    ProviderCredentialEnrollmentHostPort, ProviderCredentialHostFuture,
    ProviderCredentialIntentConsumptionProof, ProviderCredentialRequestAuthorityIssuer,
    ProviderCredentialRequestAuthorityPair, ProviderCredentialRequestAuthorityVerifier,
    ProviderCredentialStatusFuture, broker_handoff_kill_ack_binding, is_broker_handoff_frame,
};

pub use signed_installed_release::{
    CompiledUpdateTrustRootV2, MacOsCodeIdentityExpectationV1, NativeEnrollmentQualificationRowV1,
    NativeEnrollmentTupleError, NativeEnrollmentTupleV2, PendingSignedInstalledReleaseMetadataV2,
    SignedInstalledReleaseCandidateV2, SignedInstalledReleaseVerificationErrorV2,
    UpdateMetadataSigningError, UpdateMetadataV2, UpdateRootRoleV2, UpdateSignatureV2,
    UpdateSnapshotRoleV2, UpdateTargetV2, UpdateTargetsRoleV2, UpdateTimestampRoleV2,
    UpdateTrustRootV2, VerifiedSignedInstalledReleaseV2, VerifiedSignedNativeEnrollmentTupleV2,
    VerifiedSignedUpdateMetadataV2, update_metadata_signing_bytes,
    verify_exact_signed_installed_release_v2, verify_signed_update_metadata_v2,
};

pub use types::{
    BeginProviderCredentialEnrollment, ProviderCredentialBeginIntentBinding,
    ProviderCredentialEnrollmentActionV2, ProviderCredentialLastDispositionV2,
    ProviderCredentialOperationHandleV2, ProviderCredentialOperationKindV2,
    ProviderCredentialOperationSnapshotV2, ProviderCredentialOperationStateV2,
    ProviderCredentialPendingOperationV2, ProviderCredentialProviderV2,
    ProviderCredentialReadinessV2, ProviderCredentialSafeSnapshotV2, ProviderCredentialStateV2,
    ProviderCredentialValidationErrorV2, ProviderCredentialVerificationKindV2,
    ProviderCredentialVerificationStateV2, ProviderCredentialVerifyIntentBinding,
    VerifyProviderCredential,
};

/// Compile-fail contract: exact output fields cannot be constructed directly.
///
/// ```compile_fail
/// use runne_api::VerifiedSignedInstalledReleaseV2;
/// let _ = VerifiedSignedInstalledReleaseV2 { signed_candidate: panic!() };
/// ```
///
/// Compile-fail contract: the exact output is move-only.
///
/// ```compile_fail
/// use runne_api::VerifiedSignedInstalledReleaseV2;
/// fn require_clone<T: Clone>() {}
/// require_clone::<VerifiedSignedInstalledReleaseV2>();
/// ```
///
/// Compile-fail contract: exact output has no Serde or Default bridge.
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
/// let _: VerifiedSignedInstalledReleaseV2 = serde_json::from_str("{}").unwrap();
/// ```
///
/// ```compile_fail
/// use runne_api::VerifiedSignedInstalledReleaseV2;
/// let _ = VerifiedSignedInstalledReleaseV2::default();
/// ```
///
/// Compile-fail contract: candidates and generic results cannot become exact.
///
/// ```compile_fail
/// use runne_api::{SignedInstalledReleaseCandidateV2, VerifiedSignedInstalledReleaseV2};
/// fn convert(value: SignedInstalledReleaseCandidateV2) -> VerifiedSignedInstalledReleaseV2 {
///     value.into()
/// }
/// ```
///
/// ```compile_fail
/// use runne_api::{VerifiedSignedInstalledReleaseV2, VerifiedSignedUpdateMetadataV2};
/// fn convert(value: VerifiedSignedUpdateMetadataV2) -> VerifiedSignedInstalledReleaseV2 {
///     value
/// }
/// ```
///
/// Compile-fail contract: exact facts expose no native-resource accessors.
///
/// ```compile_fail
/// use runne_api::VerifiedSignedInstalledReleaseV2;
/// fn inspect(value: &VerifiedSignedInstalledReleaseV2) {
///     let _: &std::path::Path = value.path();
/// }
/// ```
///
/// ```compile_fail
/// use runne_api::VerifiedSignedInstalledReleaseV2;
/// fn inspect(value: &VerifiedSignedInstalledReleaseV2) {
///     let _: &std::fs::File = value.file();
/// }
/// ```
///
/// ```compile_fail
/// use runne_api::VerifiedSignedInstalledReleaseV2;
/// fn inspect(value: &VerifiedSignedInstalledReleaseV2) {
///     let _: i32 = value.fd();
///     let _ = value.process();
/// }
/// ```
///
/// Compile-fail contract: exact facts cannot create authority.
///
/// ```compile_fail
/// use runne_api::VerifiedSignedInstalledReleaseV2;
/// fn convert(value: VerifiedSignedInstalledReleaseV2) {
///     let _ = value.into_authority();
/// }
/// ```
///
/// ```compile_fail
/// use runne_api::VerifiedSignedInstalledReleaseV2;
/// fn convert(value: VerifiedSignedInstalledReleaseV2) {
///     let _ = value.mint();
/// }
/// ```
///
/// Compile-fail contract: there is no implementable raw-digest proof trait.
///
/// ```compile_fail
/// use runne_api::RawDigestEnrollmentProof;
/// struct CallerProof;
/// impl RawDigestEnrollmentProof for CallerProof {}
/// ```
const _: () = ();

#[cfg(test)]
mod tests;
