#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Provider-neutral contracts for Runne runtime adapters.
//!
//! Process-local credential capabilities deliberately fail durable trait bounds.
//!
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::RawCredentialTicket>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::RawCredentialTicket>();
//! ```
//! ```compile_fail
//! fn require_durable<T: Into<runne_provider::CredentialOperationSnapshot>>() {}
//! require_durable::<runne_provider::RawCredentialTicket>();
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::CredentialNativeCreateClaim>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::CredentialNativeCreateClaim>();
//! ```
//! ```compile_fail
//! fn require_durable<T: Into<runne_provider::CredentialOperationSnapshot>>() {}
//! require_durable::<runne_provider::CredentialNativeCreateClaim>();
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::CredentialGcClaim>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::CredentialGcClaim>();
//! ```
//! ```compile_fail
//! fn require_durable<T: Into<runne_provider::CredentialOperationSnapshot>>() {}
//! require_durable::<runne_provider::CredentialGcClaim>();
//! ```
//! ```compile_fail
//! let _ = runne_provider::TransitionCommand::new;
//! ```
//! ```compile_fail
//! let _ = runne_provider::CandidateSourceIdentity::from_measured([1; 32]);
//! ```
//! ```compile_fail
//! let _ = runne_provider::ExpectedInstallMeasurement::from_measured([1; 32]);
//! ```
//! ```compile_fail
//! fn require_clone<T: Clone>() {}
//! require_clone::<runne_provider::CredentialSecretClaimOffer>();
//! require_clone::<runne_provider::PendingCredentialSecretOpening>();
//! require_clone::<runne_provider::SealedCredentialEnvelope>();
//! ```
//! ```compile_fail
//! fn require_serialize<T: serde::Serialize>() {}
//! require_serialize::<runne_provider::CredentialSecretClaimOffer>();
//! require_serialize::<runne_provider::PendingCredentialSecretOpening>();
//! require_serialize::<runne_provider::SealedCredentialEnvelope>();
//! ```
//! ```compile_fail
//! use runne_provider::CredentialSecretClaimOffer;
//! let _ = CredentialSecretClaimOffer {};
//! ```
//! ```compile_fail
//! use runne_provider::CredentialSecretPublicationSigner;
//! let _ = CredentialSecretPublicationSigner::generate([1; 32]);
//! ```
//! ```compile_fail
//! fn cannot_expose(envelope: runne_provider::SealedCredentialEnvelope) {
//!     let _ = envelope.into_vec();
//! }
//! ```
//! ```compile_fail
//! use runne_provider::CredentialBrokerFrame;
//! fn cannot_mint_seal_capability(frame: CredentialBrokerFrame) {
//!     let CredentialBrokerFrame::ClaimAccepted { .. } = frame else { return };
//!     let _ = frame.seal(Vec::new());
//! }
//! ```
//! ```compile_fail
//! fn cannot_use_generic_secret_callback(envelope: runne_provider::SealedCredentialEnvelope) {
//!     envelope.with_secret(|_| ());
//! }
//! ```
//! ```compile_fail
//! use runne_provider::{
//!     AuthorizedCredentialSecretOpening, CredentialDecryptedMaterial,
//!     CredentialSecretPublicationVerifier, OpenedCredentialSecretEffect,
//!     VerifiedCredentialSecretOffer,
//! };
//! fn raw_credential_capabilities_are_not_external(
//!     verifier: CredentialSecretPublicationVerifier,
//!     verified: VerifiedCredentialSecretOffer,
//!     authorization: AuthorizedCredentialSecretOpening,
//!     material: CredentialDecryptedMaterial,
//!     effect: OpenedCredentialSecretEffect,
//! ) {
//!     let _ = (verifier, verified, authorization, material, effect);
//! }
//! ```
mod coordination;
mod credential;
mod digest;
mod fake;
mod id;
mod model;
mod port;
mod prepared;
mod pricing;
mod recovery;
mod stream;
mod text_profile;

pub use coordination::{
    PreparedProviderRecord, ProviderDispatchClaim, ProviderDispatchRepository,
    ProviderPreEffectRejection, ProviderRepositoryClaimOutcome, ProviderRepositoryError,
    ProviderRepositoryState,
};
#[doc(hidden)]
pub use credential::daemon_credential_publication;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use credential::daemon_credential_publication_test_support;
pub use credential::{
    AttachCredentialProcess, BeginCredentialOperation, BeginCredentialOperationOutcome,
    BeginCredentialVerification, BindCredentialReadback, BrokerChannelBinding,
    CandidateSourceIdentity, ClaimCredentialOperation, ClaimedWriterAuthorization,
    ClosePreparedCredentialOperation, CompleteCredentialOperation, CompleteCredentialVerification,
    ContinuationBindingDigest, ContractBundleDigest, CredentialAuthorityPair,
    CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerCommandCodec,
    CredentialBrokerFrame, CredentialBrokerFrameCodec, CredentialBrokerTarget,
    CredentialClaimBinding, CredentialCompletionReceipt, CredentialDispatchCapability,
    CredentialDisposition, CredentialEnrollmentAuthorityPair, CredentialEnrollmentError,
    CredentialEnrollmentMeasurementAuthority, CredentialEnrollmentStoreAuthority, CredentialFence,
    CredentialGcClaim, CredentialInstallationOwnerId, CredentialLease,
    CredentialLifecycleAuthority, CredentialLifecycleError, CredentialLifecycleRevision,
    CredentialLifecycleSnapshot, CredentialMeasurementSnapshot, CredentialMigrationMetadata,
    CredentialNativeCreateAuthorization, CredentialNativeCreateClaim, CredentialNativeCreateIssuer,
    CredentialNativeCreateProgression, CredentialNativeCreateValidator,
    CredentialNativeEffectDisposition, CredentialOperationAction, CredentialOperationId,
    CredentialOperationMetadata, CredentialOperationSnapshot, CredentialOperationState,
    CredentialProcessBinding, CredentialProvisionSource, CredentialQualifiedReleaseTuple,
    CredentialReadbackDisposition, CredentialReadinessDisposition, CredentialReadinessObservation,
    CredentialReadinessRevision, CredentialRecoveryWork, CredentialReleaseMigrationBinding,
    CredentialSafeSnapshot, CredentialSecretClaimOffer, CredentialSecretEnvelopeCodec,
    CredentialSecretOfferCodec, CredentialSecretPublication, CredentialSecretPublicationCodec,
    CredentialTerminalDisposition, CredentialTicketAttempt, CredentialTransitionEvidence,
    CredentialVerificationCapability, CredentialVerificationContext, CredentialVerificationKind,
    CredentialVerificationLease, CredentialVerificationObservation, CredentialVerificationResult,
    CredentialVerificationSnapshot, CredentialVerifierRevision, CredentialVersionRef,
    CredentialVersionState, CredentialWriterAuthorityPair, CredentialWriterClaimIssuer,
    CredentialWriterEffectAuthority, DaemonAuthorityId, DesktopExecutableIdentity,
    DesktopSupervisorGeneration, ExpectedInstallMeasurement, FailCredentialOperation,
    HardFenceProvider, IssueCredentialTicketDigest, IssuedCredentialTicketAttempt,
    NativeCredentialAuthority, NativeCredentialDeletionProof, ObserveNativeEffect,
    ObservedInstallMeasurement, PROVIDER_CREDENTIAL_BROKER_MODE_V1, PendingCredentialSecretOpening,
    PendingCredentialWriterClaim, PrepareCredentialVersion, ProtectedSessionId,
    ProviderCredentialEnrollmentStore, ProviderCredentialVersionStore, RawCredentialTicket,
    ReaderExecutableIdentity, ReconcileCredentialVersions, ReleaseManifestDigest,
    RevokeCredentialVersion, SealedCredentialEnvelope, TombstoneCredentialOperation,
    TransitionCommand, WriterExecutableIdentity, WriterIdentityMigrationPhase, WriterLaunchId,
    WriterProcessHandleIdentity, WriterProcessStartIdentity, allows_structural_transition,
};
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use credential::{SealedPairFixture, sealed_pair_for_test};
pub use digest::{
    CanonicalProviderError, ProviderCallDigest, ProviderCallDigestVersion,
    canonical_provider_call_digest, canonical_provider_call_digest_for_version,
    provider_call_wire_bytes_for_version,
};
pub use fake::{ScriptedProvider, ScriptedProviderError};
pub use id::{DispatchAttemptId, InvalidProviderId, ProviderCallId, ProviderId, ProviderStreamId};
pub use model::{
    MAX_PROVIDER_TEXT_INPUT_BYTES, MAX_PROVIDER_TEXT_INPUT_TOTAL_BYTES, MAX_PROVIDER_TEXT_INPUTS,
    ModelRef, ProviderCall, ProviderCallError, ProviderCapability, ProviderFinishReason,
    ProviderInputRole, ProviderTextInput,
};
pub use port::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, DispatchRequestError,
    PrepareError, ProviderFuture, ProviderPort, ReconcileRequest, ReconciliationDisposition,
};
pub use prepared::{PreparedRequest, PreparedRequestRef};
pub use pricing::{ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError};
pub use recovery::{
    CredentialMatcher, NativeSecretRef, ScanStep, ScannerCheckpoint, ScannerError,
    ScannerTerminalDisposition, ScannerUncertainReason, SecureStoreError, TailBinding,
    WithheldTailStore, scan_provider_chunk,
};
pub use stream::{
    MAX_PROVIDER_TEXT_DELTA_BYTES, MAX_PROVIDER_TOOL_ARGUMENT_BYTES,
    MAX_PROVIDER_TOOL_IDENTIFIER_BYTES, MAX_PROVIDER_USAGE_TOKENS, ProviderStreamEvent,
    ProviderStreamEventKind, ProviderStreamItem, ProviderStreamValidator,
    ProviderTerminalDisposition, ProviderUsage, ProviderUsageError, StreamCursor, StreamError,
};
pub use text_profile::TextProviderProfile;
