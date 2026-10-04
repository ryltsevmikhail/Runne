#[cfg(feature = "desktop-protected")]
use super::root_handle_admission::RootAdmissionGateway;
use super::*;
use runne_application::ports::{ExecutionNodeId, TaskRunAssignmentIdentity};
use runne_runtime::taskrun_auto_worker::AutomaticTaskRunError;
use std::sync::{Arc, atomic::AtomicU64};
#[path = "exec_taskrun_worker/context.rs"]
mod context;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
mod local;
#[path = "exec_taskrun_worker/logging.rs"]
mod logging;
#[path = "exec_taskrun_worker/provider.rs"]
mod provider;

pub(crate) struct DaemonAutomaticTaskRuns {
    pub(super) store: StoreTransaction,
    pub(super) taskruns: Arc<SqliteTaskRunService>,
    pub(super) text: Arc<dyn ConversationTextCommandService>,
    pub(super) provider: Option<Arc<DaemonCanonicalProviderService>>,
    pub(super) node_id: ExecutionNodeId,
    pub(super) epoch: u64,
    pub(super) current_epoch: Arc<AtomicU64>,
    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
    pub(super) node_lease_heartbeat: Arc<dyn Fn() -> Result<(), ()> + Send + Sync>,
    #[cfg(all(test, feature = "desktop-protected", target_os = "linux"))]
    pub(super) provider_only_test_fixture: bool,
    #[cfg(feature = "desktop-protected")]
    pub(super) root_admission: RootAdmissionGateway,
}

#[cfg(feature = "desktop-protected")]
pub(crate) struct ProtectedTaskRunWorkerConfig {
    pub(crate) store: StoreTransaction,
    pub(crate) taskruns: Arc<SqliteTaskRunService>,
    pub(crate) text: Arc<dyn ConversationTextCommandService>,
    pub(crate) provider: Option<Arc<DaemonCanonicalProviderService>>,
    pub(crate) node_id: ExecutionNodeId,
    pub(crate) epoch: u64,
    pub(crate) current_epoch: Arc<AtomicU64>,
    pub(crate) root_admission: RootAdmissionGateway,
    #[cfg(target_os = "linux")]
    pub(crate) node_lease_heartbeat: Arc<dyn Fn() -> Result<(), ()> + Send + Sync>,
}

impl DaemonAutomaticTaskRuns {
    #[cfg(any(test, not(feature = "desktop-protected")))]
    pub(crate) fn new(
        store: StoreTransaction,
        taskruns: Arc<SqliteTaskRunService>,
        text: Arc<dyn ConversationTextCommandService>,
        provider: Option<Arc<DaemonCanonicalProviderService>>,
        node_id: ExecutionNodeId,
        epoch: u64,
        current_epoch: Arc<AtomicU64>,
    ) -> Self {
        #[cfg(feature = "desktop-protected")]
        return Self {
            store,
            taskruns,
            text,
            provider,
            node_id,
            epoch,
            current_epoch,
            root_admission: RootAdmissionGateway::unavailable(),
            #[cfg(target_os = "linux")]
            node_lease_heartbeat: Arc::new(|| Err(())),
            #[cfg(all(test, target_os = "linux"))]
            provider_only_test_fixture: false,
        };
        #[cfg(not(feature = "desktop-protected"))]
        Self {
            store,
            taskruns,
            text,
            provider,
            node_id,
            epoch,
            current_epoch,
        }
    }

    #[cfg(feature = "desktop-protected")]
    pub(crate) fn new_with_root(config: ProtectedTaskRunWorkerConfig) -> Self {
        Self {
            store: config.store,
            taskruns: config.taskruns,
            text: config.text,
            provider: config.provider,
            node_id: config.node_id,
            epoch: config.epoch,
            current_epoch: config.current_epoch,
            root_admission: config.root_admission,
            #[cfg(target_os = "linux")]
            node_lease_heartbeat: config.node_lease_heartbeat,
            #[cfg(all(test, target_os = "linux"))]
            provider_only_test_fixture: false,
        }
    }

    #[cfg(all(test, feature = "desktop-protected", target_os = "linux"))]
    pub(crate) fn new_provider_only_test_fixture(
        store: StoreTransaction,
        taskruns: Arc<SqliteTaskRunService>,
        text: Arc<dyn ConversationTextCommandService>,
        provider: Option<Arc<DaemonCanonicalProviderService>>,
        node_id: ExecutionNodeId,
        epoch: u64,
        current_epoch: Arc<AtomicU64>,
    ) -> Self {
        let mut worker = Self::new(
            store,
            taskruns,
            text,
            provider,
            node_id,
            epoch,
            current_epoch,
        );
        worker.provider_only_test_fixture = true;
        worker
    }

    pub(super) fn release_before_effect(
        &self,
        identity: TaskRunAssignmentIdentity,
        version: u64,
    ) -> Result<(), AutomaticTaskRunError> {
        let context = Self::runtime_context();
        let candidate = runne_application::ports::TaskRunNoEffectCandidate {
            identity,
            current_version: version,
        };
        self.taskruns
            .settle_taskrun_no_effect(&context, candidate, &self.store)
            .map(|_| ())
            .map_err(|_| AutomaticTaskRunError::Uncertain)
    }
}
