mod authority;
mod binding;
mod identity;
mod metadata;
mod operation;
mod operation_metadata;
mod protocol;
mod snapshot;
mod state;
mod store;
mod verification;

#[allow(unused_imports)]
pub use authority::{
    CredentialEnrollmentAuthorityPair, CredentialEnrollmentMeasurementAuthority,
    CredentialEnrollmentStoreAuthority,
};
pub use binding::{
    BrokerChannelBinding, CandidateSourceIdentity, ContinuationBindingDigest, ContractBundleDigest,
    CredentialClaimBinding, CredentialMeasurementSnapshot, CredentialProcessBinding,
    CredentialReleaseMigrationBinding, DaemonAuthorityId, DesktopExecutableIdentity,
    ExpectedInstallMeasurement, ObservedInstallMeasurement, ProtectedSessionId,
    ReaderExecutableIdentity, ReleaseManifestDigest, WriterExecutableIdentity,
    WriterIdentityMigrationPhase, WriterLaunchId, WriterProcessHandleIdentity,
    WriterProcessStartIdentity,
};
pub use identity::{
    CredentialBindingDigest, CredentialFence, CredentialLifecycleRevision, CredentialOperationId,
    CredentialTicketAttempt, RawCredentialTicket,
};
pub use metadata::{
    CredentialNativeEffectDisposition, CredentialReadbackDisposition,
    CredentialReadinessDisposition, CredentialReadinessObservation, CredentialReadinessRevision,
    CredentialTerminalDisposition, CredentialVerificationKind, CredentialVerificationResult,
    CredentialVerifierRevision,
};
pub use operation::{
    BeginCredentialOperation, BindCredentialReadback, ClaimCredentialOperation,
    ClosePreparedCredentialOperation, CompleteCredentialOperation, FailCredentialOperation,
    IssueCredentialTicketDigest, ObserveNativeEffect, TombstoneCredentialOperation,
};
pub use operation_metadata::{CredentialMigrationMetadata, CredentialOperationMetadata};
pub use protocol::{CredentialBrokerFrame, CredentialBrokerFrameCodec};
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
