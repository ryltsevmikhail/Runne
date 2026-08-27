mod authority;
mod binding;
mod completion_receipt;
mod identity;
mod metadata;
mod operation;
mod operation_metadata;
mod projection;
mod protocol;
mod qualified_release;
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
    CredentialEnrollmentAuthorityPair, CredentialEnrollmentMeasurementAuthority,
    CredentialEnrollmentStoreAuthority,
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
pub use operation_metadata::{CredentialMigrationMetadata, CredentialOperationMetadata};
#[allow(unused_imports)]
pub use projection::{CredentialSafeSnapshot, CredentialVerificationSnapshot};
pub use protocol::{
    CredentialBrokerCommand, CredentialBrokerCommandCodec, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialBrokerTarget,
};
pub use qualified_release::CredentialQualifiedReleaseTuple;
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
    CredentialVerificationLease, CredentialVerificationObservation,
};

#[cfg(test)]
mod tests;
