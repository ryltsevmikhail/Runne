use super::*;
use runne_runtime::canonical_provider_execution::CanonicalProviderExecutionError;

impl DaemonCanonicalProviderService {
    pub(super) async fn acquire_dispatch_gate(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.renewal_dispatch_gate.lock().await
    }

    pub(super) fn renew_launch_authority(&self) -> Result<(), CanonicalProviderExecutionError> {
        self.execution_store
            .renew_runtime_launch_lease(&self.launch_capability)
            .map(|_| ())
            .map_err(|error| {
                let stage = super::execution_diagnostics::admission_failure_stage(&error);
                super::execution_diagnostics::record(stage, false);
                super::projection::map_admission_error(error)
            })
    }
}
