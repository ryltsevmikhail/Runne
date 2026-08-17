use std::sync::Arc;

use gocode_observability::operational::RecoveryObservationRegistry;
use gocode_provider::TextProviderProfile;
use gocode_store::provider::SqliteProviderExecutionStore;

use super::DaemonCanonicalProviderService;
use crate::operational_telemetry::{
    DaemonOperationalTelemetryCompositionError, DaemonTelemetryLaunchContext,
};

impl DaemonCanonicalProviderService {
    pub(crate) fn operational_telemetry_store(&self) -> Arc<SqliteProviderExecutionStore> {
        Arc::clone(&self.execution_store)
    }

    pub(crate) fn recovery_observation_registry(&self) -> Arc<RecoveryObservationRegistry> {
        Arc::clone(&self.recovery_registry)
    }

    pub(crate) fn telemetry_launch_context(
        &self,
        authenticated_launch_generation: u64,
    ) -> Result<DaemonTelemetryLaunchContext, DaemonOperationalTelemetryCompositionError> {
        DaemonTelemetryLaunchContext::from_retained_fields(
            self.runtime_authority_id,
            self.database_generation,
            self.runtime_generation,
            self.fencing_token,
            self.profile.profile_digest(),
            authenticated_launch_generation,
        )
    }
}
