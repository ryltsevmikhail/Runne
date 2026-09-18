mod authority;
mod binding;
mod completion_receipt;
mod identity;
mod measured_qualification;
mod metadata;
mod operation;
mod operation_metadata;
mod projection;
mod protocol;
mod qualification_fence;
mod qualification_fence_receipt;
mod qualified_release;
mod recovery_admission;
mod service_protocol;
mod service_qualification_protocol;
mod snapshot;
mod state;
mod store;
mod verification;

pub use authority::writer::{
    ClaimedWriterAuthorization, CredentialWriterAuthorityPair, CredentialWriterClaimIssuer,
    CredentialWriterEffectAuthority, PendingCredentialWriterClaim,
};
#[allow(unused_imports)]
pub use authority::{
    CredentialDispatchEffectReceiptAuthority, CredentialEnrollmentAuthorityPair,
    CredentialEnrollmentMeasurementAuthority, CredentialEnrollmentStoreAuthority,
    CredentialLegacyImportAuthorization, CredentialRuntimeArmAuthority,
    CredentialRuntimeReadAuthority,
};
pub use binding::{
    BrokerChannelBinding, CandidateSourceIdentity, ContinuationBindingDigest, ContractBundleDigest,
    CredentialClaimBinding, CredentialMeasurementSnapshot, CredentialProcessBinding,
    CredentialReleaseMigrationBinding, DaemonAuthorityId, DesktopExecutableIdentity,
    DesktopSupervisorGeneration, ExpectedInstallMeasurement, ObservedInstallMeasurement,
    ProtectedSessionId, ReaderExecutableIdentity, ReleaseManifestDigest, WriterExecutableIdentity,
    WriterIdentityMigrationPhase, WriterLaunchId, WriterProcessHandleIdentity,
    WriterProcessStartIdentity,
};
pub use completion_receipt::CredentialCompletionReceipt;
pub use identity::{
    CredentialBindingDigest, CredentialFence, CredentialInstallationOwnerId,
    CredentialLifecycleRevision, CredentialOperationId, CredentialTicketAttempt,
    RawCredentialTicket,
};
pub use measured_qualification::{MeasuredQualificationAdmission, QualificationSessionBinding};
pub use metadata::{
    CredentialNativeEffectDisposition, CredentialReadbackDisposition,
    CredentialReadinessDisposition, CredentialReadinessObservation, CredentialReadinessRevision,
    CredentialTerminalDisposition, CredentialVerificationKind, CredentialVerificationResult,
    CredentialVerifierRevision,
};
pub use operation::{
    AttachCredentialProcess, BeginCredentialOperation, BeginCredentialOperationOutcome,
    BindCredentialReadback, ClaimCredentialOperation, ClosePreparedCredentialOperation,
    CompleteCredentialOperation, FailCredentialOperation, IssueCredentialTicketDigest,
    IssuedCredentialTicketAttempt, ObserveNativeEffect, TombstoneCredentialOperation,
};
pub use operation_metadata::{
    CredentialLegacyCleanupBinding, CredentialMigrationMetadata, CredentialOperationMetadata,
};
#[allow(unused_imports)]
pub use projection::{CredentialSafeSnapshot, CredentialVerificationSnapshot};
#[doc(hidden)]
pub use protocol::daemon_credential_publication;
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use protocol::daemon_credential_publication_test_support;
pub use protocol::{
    CredentialBrokerCommand, CredentialBrokerCommandCodec, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialBrokerTarget, CredentialIssueTicketBindingV1,
    CredentialSecretClaimOffer, CredentialSecretEnvelopeCodec, CredentialSecretEnvelopeKind,
    CredentialSecretInputPresence, CredentialSecretOfferCodec, CredentialSecretPublication,
    CredentialSecretPublicationCodec, CredentialSecretRelayFrameCodec,
    CredentialWriterCommandKindV1, CredentialWriterCommandScopeV1,
    CredentialWriterQualifiedAckCodec, CredentialWriterQualifiedAckSigner,
    CredentialWriterQualifiedAckV1, CredentialWriterQualifiedPreludeCodec,
    CredentialWriterQualifiedPreludeSigner, CredentialWriterQualifiedPreludeV1,
    CredentialWriterSessionAttestationClaimsV1, CredentialWriterSessionAttestationCodec,
    CredentialWriterSessionAttestationV2Codec, CredentialWriterSessionProcessClaimsV1,
    CredentialWriterSessionRuntimeClaimsV1, CredentialWriterSessionTicketClaimsV1,
    PROVIDER_CREDENTIAL_BROKER_MODE_V1, PendingCredentialIssueTicketV1,
    PendingCredentialSecretOpening, SealedCredentialEnvelope,
    SignedCredentialWriterSessionAttestationV1, SignedCredentialWriterSessionAttestationV2,
};
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub use protocol::{SealedPairFixture, sealed_pair_for_test};
pub use qualification_fence::ProviderQualificationAdmissionFence;
pub use qualification_fence_receipt::ProviderQualificationAdmissionFenceReceipt;
pub use qualified_release::CredentialQualifiedReleaseTuple;
pub use recovery_admission::{AcceptedCredentialCleanupRecovery, CredentialCleanupRecoveryRequest};
pub use service_protocol::{
    AuthorizedCredentialLegacyRead, CredentialDispatchEffectReceipt, CredentialLegacyReadVerifier,
    CredentialLegacySourceMaterial, CredentialMaterial, CredentialMetadataReadbackAdmission,
    CredentialMetadataReadbackRequest, CredentialMutationGrant, CredentialMutationGrantDigest,
    CredentialPointOfUseReadAdmission, CredentialPointOfUseReadRequest,
    CredentialRuntimeMutationAdmission, CredentialRuntimeMutationArmRequest,
    CredentialRuntimeMutationPlan, CredentialRuntimeReadBinding, CredentialServiceCorrelation,
    CredentialServiceDeadline, CredentialServiceDisposition, CredentialServiceEndpointRole,
    CredentialServiceEpoch, CredentialServiceIngressRequest, CredentialServiceProtocolCodec,
    CredentialServiceReconciliationRequired, CredentialServiceReply, CredentialServiceReplyFrame,
    CredentialServiceRequest, CredentialServiceRequestContext, CredentialServiceRequestFrame,
    CredentialServiceRequestKind, CredentialServiceRequestSequence,
    CredentialWriterBrokerHandoffFrame, CredentialWriterConsumeRequest,
    CredentialWriterIngressRequest, CredentialWriterServiceBindingHandoff,
};
#[allow(unused_imports)]
pub use service_qualification_protocol::{
    ServiceQualificationCommon, ServiceQualificationProtocolCodec,
    ServiceQualificationRejectionCode, ServiceQualificationReplyFrame, ServiceQualificationRequest,
    ServiceQualificationRequestKind, ServiceQualificationRequestPayload,
};
pub use snapshot::{
    CredentialLifecycleSnapshot, CredentialOperationSnapshot, CredentialRecoveryWork,
    HardFenceProvider,
};
pub use state::{
    CredentialDisposition, CredentialEnrollmentError, CredentialOperationAction,
    CredentialOperationState, CredentialTransitionEvidence, TransitionCommand,
    allows_structural_transition,
};
pub use store::ProviderCredentialEnrollmentStore;
pub use verification::{
    BeginCredentialVerification, CompleteCredentialVerification, CredentialVerificationCapability,
    CredentialVerificationContext, CredentialVerificationLease, CredentialVerificationObservation,
};

#[cfg(test)]
mod tests;
