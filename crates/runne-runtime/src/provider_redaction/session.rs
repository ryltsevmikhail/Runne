use runne_provider::{
    CredentialMatcher, ScannerCheckpoint, ScannerTerminalDisposition, TailBinding,
    WithheldTailStore,
};

use super::diagnostics::{ProviderRedactionObserver, RedactionFailureKind, RedactionFailureSite};
use super::types::ScannerRecoveryPersistence;

mod constructors;
mod ingest;

/// Runtime-owned pre-journal scanner session.
pub struct ProviderRedactionRecovery<'a, T: ?Sized, P: ?Sized, M: ?Sized> {
    pub(in crate::provider_redaction) tail_store: &'a T,
    pub(in crate::provider_redaction) persistence: &'a P,
    pub(in crate::provider_redaction) matcher: &'a M,
    pub(in crate::provider_redaction) binding: TailBinding,
    pub(in crate::provider_redaction) checkpoint: Option<ScannerCheckpoint>,
    pub(in crate::provider_redaction) disposition: Option<ScannerTerminalDisposition>,
    pub(in crate::provider_redaction) observer: Option<&'a dyn ProviderRedactionObserver>,
}

impl<T, P, M> ProviderRedactionRecovery<'_, T, P, M>
where
    T: WithheldTailStore + ?Sized,
    P: ScannerRecoveryPersistence + ?Sized,
    M: CredentialMatcher + ?Sized,
{
    pub(super) fn observe_failure(&self, site: RedactionFailureSite, kind: RedactionFailureKind) {
        if let Some(observer) = self.observer {
            observer.observe_failure(site, kind);
        }
    }
}
