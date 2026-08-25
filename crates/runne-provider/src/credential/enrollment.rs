mod binding;
mod identity;
mod operation;
mod protocol;
mod snapshot;
mod state;
mod verification;

#[allow(unused_imports)]
pub use binding::{
    BrokerChannelBinding, CandidateSourceIdentity, ContinuationBindingDigest, ContractBundleDigest,
    CredentialClaimBinding, CredentialMeasurementSnapshot, CredentialProcessBinding,
    CredentialReleaseMigrationBinding, DaemonAuthorityId, DesktopExecutableIdentity,
    ProtectedSessionId, ReaderExecutableIdentity, ReleaseManifestDigest, WriterExecutableIdentity,
    WriterIdentityMigrationPhase, WriterLaunchId, WriterProcessHandleIdentity,
    WriterProcessStartIdentity,
};
pub use identity::{
    CredentialBindingDigest, CredentialFence, CredentialLifecycleRevision, CredentialOperationId,
    CredentialTicketAttempt, RawCredentialTicket,
};
pub use operation::{
    BeginCredentialOperation, BindCredentialReadback, ClaimCredentialOperation,
    ClosePreparedCredentialOperation, CompleteCredentialOperation, FailCredentialOperation,
    IssueCredentialTicketDigest, ObserveNativeEffect, TombstoneCredentialOperation,
};
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
pub use verification::{
    BeginCredentialVerification, CompleteCredentialVerification, CredentialVerificationCapability,
    CredentialVerificationLease, CredentialVerificationObservation,
};

#[cfg(test)]
mod tests;
