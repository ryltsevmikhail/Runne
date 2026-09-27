use runne_runtime::provider_redaction::{
    ProviderRedactionObserver, RedactionFailureKind, RedactionFailureSite,
};

pub(super) static QUALIFICATION_OBSERVER: QualificationObserver = QualificationObserver;

pub(super) struct QualificationObserver;

impl ProviderRedactionObserver for QualificationObserver {
    fn observe_failure(&self, site: RedactionFailureSite, kind: RedactionFailureKind) {
        super::execution_diagnostics::record(site.stage(), false);
        super::execution_diagnostics::record(kind.stage(), false);
    }
}
