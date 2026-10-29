#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Provider-neutral contracts for Runne runtime adapters.
//!
//! Process-local credential capabilities deliberately fail durable trait bounds.
//!
pub use runne_domain::id::{AttemptId, TaskRunId};

mod contract_doctests;
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
mod recovery_artifact;
mod recovery_context;
mod recovery_control;
mod recovery_identity;
mod recovery_operation;
mod recovery_request;
mod stream;
mod text_profile;

include!("credential_service_exports.rs");

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
    AcceptedCredentialCleanupRecovery, AttachCredentialProcess, BeginCredentialOperation,
    BeginCredentialOperationOutcome, BeginCredentialVerification, BindCredentialReadback,
    BrokerChannelBinding, CandidateSourceIdentity, ClaimCredentialOperation,
    ClaimedWriterAuthorization, ClosePreparedCredentialOperation, CompleteCredentialOperation,
    CompleteCredentialVerification, ContinuationBindingDigest, ContractBundleDigest,
    CredentialAuthorityPair, CredentialBindingDigest, CredentialBrokerCommand,
    CredentialBrokerCommandCodec, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialBrokerTarget, CredentialClaimBinding, CredentialCleanupRecoveryRequest,
    CredentialCliHostInstallationBinding, CredentialCompletionReceipt,
    CredentialDispatchCapability, CredentialDisposition, CredentialEnrollmentAuthorityPair,
    CredentialEnrollmentError, CredentialEnrollmentMeasurementAuthority,
    CredentialEnrollmentStoreAuthority, CredentialFence, CredentialGcClaim,
    CredentialInstallationOwnerId, CredentialIssueTicketBindingV1, CredentialLease,
    CredentialLegacyCleanupBinding, CredentialLifecycleAuthority, CredentialLifecycleError,
    CredentialLifecycleRevision, CredentialLifecycleSnapshot, CredentialMeasurementSnapshot,
    CredentialMigrationMetadata, CredentialNativeCreateAuthorization, CredentialNativeCreateClaim,
    CredentialNativeCreateIssuer, CredentialNativeCreateProgression,
    CredentialNativeCreateValidator, CredentialNativeEffectDisposition, CredentialOperationAction,
    CredentialOperationId, CredentialOperationMetadata, CredentialOperationSnapshot,
    CredentialOperationState, CredentialProcessBinding, CredentialProvisionSource,
    CredentialQualifiedReleaseTuple, CredentialReadbackDisposition, CredentialReadinessDisposition,
    CredentialReadinessObservation, CredentialReadinessRevision, CredentialRecoveryWork,
    CredentialReleaseMigrationBinding, CredentialSafeSnapshot, CredentialSecretClaimOffer,
    CredentialSecretEnvelopeCodec, CredentialSecretEnvelopeKind, CredentialSecretInputPresence,
    CredentialSecretOfferCodec, CredentialSecretPublication, CredentialSecretPublicationCodec,
    CredentialSecretRelayFrameCodec, CredentialTerminalDisposition, CredentialTicketAttempt,
    CredentialTransitionEvidence, CredentialVerificationCapability, CredentialVerificationContext,
    CredentialVerificationKind, CredentialVerificationLease, CredentialVerificationObservation,
    CredentialVerificationResult, CredentialVerificationSnapshot, CredentialVerifierRevision,
    CredentialVersionRef, CredentialVersionState, CredentialWriterAuthorityPair,
    CredentialWriterClaimIssuer, CredentialWriterCommandKindV1, CredentialWriterCommandScopeV1,
    CredentialWriterEffectAuthority, CredentialWriterSessionAttestationClaimsV1,
    CredentialWriterSessionAttestationCodec, CredentialWriterSessionProcessClaimsV1,
    CredentialWriterSessionRuntimeClaimsV1, CredentialWriterSessionTicketClaimsV1,
    DaemonAuthorityId, DesktopExecutableIdentity, DesktopSupervisorGeneration,
    ExpectedInstallMeasurement, FailCredentialOperation, HardFenceProvider,
    IssueCredentialTicketDigest, IssuedCredentialTicketAttempt, MeasuredQualificationAdmission,
    NativeCredentialAuthority, NativeCredentialDeletionProof, ObserveNativeEffect,
    ObservedInstallMeasurement, PROVIDER_CREDENTIAL_BROKER_MODE_V1, PendingCredentialIssueTicketV1,
    PendingCredentialSecretOpening, PendingCredentialWriterClaim, PrepareCredentialVersion,
    ProtectedSessionId, ProviderCredentialEnrollmentStore, ProviderCredentialVersionStore,
    ProviderQualificationAdmissionFence, ProviderQualificationAdmissionFenceReceipt,
    QualificationSessionBinding, RawCredentialTicket, ReaderExecutableIdentity,
    ReconcileCredentialVersions, ReleaseManifestDigest, RevokeCredentialVersion,
    SealedCredentialEnvelope, SignedCredentialWriterSessionAttestationV1,
    TombstoneCredentialOperation, TransitionCommand, WriterExecutableIdentity,
    WriterIdentityMigrationPhase, WriterLaunchId, WriterProcessHandleIdentity,
    WriterProcessStartIdentity, allows_structural_transition,
};
#[cfg(target_os = "linux")]
pub use credential::{
    LinuxWriterStartup, encode_linux_writer_startup_payload, linux_writer_self_measurements,
    respond_linux_writer_startup,
};

#[rustfmt::skip]
pub use credential::{CredentialWriterQualifiedAckCodec, CredentialWriterQualifiedAckSigner, CredentialWriterQualifiedAckV1, CredentialWriterQualifiedPreludeCodec, CredentialWriterQualifiedPreludeSigner, CredentialWriterQualifiedPreludeV1, CredentialWriterSessionAttestationV2Codec, SignedCredentialWriterSessionAttestationV2};
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
    MAX_PROVIDER_TOOL_ARGUMENT_CONTEXT_BYTES, MAX_PROVIDER_TOOL_CALL_ID_BYTES,
    MAX_PROVIDER_TOOL_CONTENT_BYTES, MAX_PROVIDER_TOOL_RESULT_BYTES, ModelRef, ProviderCall,
    ProviderCallError, ProviderCapability, ProviderFinishReason, ProviderInputRole,
    ProviderTextInput, ProviderToolDeclarationV1, ProviderToolNameV1, ProviderToolResultV1,
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
pub use recovery_artifact::{
    ProviderRemoteCheck, ProviderRemotePublicationDisposition, ProviderRemoteTerminalArtifact,
};
pub use recovery_context::{
    ProviderRecoveryAuthorization, ProviderRecoveryControlAuthorizer,
    ProviderRecoveryDispatchContext, ProviderRecoveryDispatchContextProvider,
    ProviderRecoveryOperation,
};
pub use recovery_control::{
    ProviderRecoveryBinding, ProviderRecoveryCapabilities, ProviderRecoveryError,
    ProviderRemoteResponseStatus, ProviderResponseIdentityCommitter, RemoteResponseId,
    RemoteStreamCursor,
};
pub use recovery_identity::ProviderRecoveryAttemptIdentity;
pub use recovery_operation::ProviderRemoteOperationProof;
pub use recovery_request::{ProviderRecoveryRequest, ProviderResumeRequest};
pub use stream::{
    MAX_PROVIDER_TEXT_DELTA_BYTES, MAX_PROVIDER_TOOL_ARGUMENT_BYTES,
    MAX_PROVIDER_TOOL_IDENTIFIER_BYTES, MAX_PROVIDER_USAGE_TOKENS, ProviderStreamEvent,
    ProviderStreamEventKind, ProviderStreamItem, ProviderStreamValidator,
    ProviderTerminalDisposition, ProviderUsage, ProviderUsageError, StreamCursor, StreamError,
};
pub use text_profile::{TextProviderProfile, ToolProviderProfile};
