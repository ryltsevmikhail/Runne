//! Pre-journal provider-byte withholding and fail-closed restart orchestration.
mod boundary;
mod completion;
mod diagnostics;
mod session;
mod state;
mod surfaces;
mod types;

pub use boundary::{
    PreJournalProviderEvent, ProhibitedContentCredentialMatcher, ProviderEventRedaction,
    ProviderEventRedactionBoundary,
};
pub use diagnostics::{ProviderRedactionObserver, RedactionFailureKind, RedactionFailureSite};
pub use session::ProviderRedactionRecovery;
pub use types::{
    ProviderRedactionError, ScannerRecoveryPersistence, ScannerRecoveryPersistenceError,
    ScannerRecoveryRecord,
};
