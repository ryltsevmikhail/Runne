//! Provider effect admission and application coordination.

mod admission;
mod authority;
mod coordinator;
mod execution;

pub use admission::{ProviderAdmissionError, ProviderEffectAuthorityRef};
pub use authority::{
    AdmittedProviderDispatch, ProviderAuthorityIssueOutcome, ProviderAuthorityIssueRequest,
    ProviderAuthorityIssuerDecision, RuntimeProviderAuthorityIssuer,
};
pub use coordinator::{
    ProviderCoordinatorOutcome, ProviderCoordinatorRequest, ProviderDispatchCoordinator,
};
pub use execution::{
    ProviderEncryptedPayload, ProviderExecutionError, ProviderExecutionStore,
    ProviderJournalAppendOutcome, ProviderJournalAppendRequest, ProviderJournalKeyBinding,
    ProviderPollRequest, ProviderTerminalCommitOutcome, ProviderTerminalOutboxRecord,
    ProviderTerminalPricingBinding,
};
