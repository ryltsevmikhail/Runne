mod binding;
mod identity;
mod protocol;
mod state;

#[allow(unused_imports)]
pub use binding::{
    CredentialClaimBinding, CredentialProcessBinding, CredentialReleaseMigrationBinding,
    WriterIdentityMigrationPhase,
};
pub use identity::{
    CredentialBindingDigest, CredentialFence, CredentialLifecycleRevision, CredentialOperationId,
    CredentialTicketAttempt, RawCredentialTicket,
};
pub use protocol::{CredentialBrokerFrame, CredentialBrokerFrameCodec};
pub use state::{
    CredentialDisposition, CredentialEnrollmentError, CredentialOperationAction,
    CredentialOperationState, CredentialTransitionEvidence, TransitionCommand,
    allows_structural_transition,
};

#[cfg(test)]
mod tests;
