use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn compose(
    store: StoreTransaction,
    service: Arc<SqliteTaskRunService>,
    text: Arc<dyn ConversationTextCommandService>,
    provider: Option<Arc<DaemonCanonicalProviderService>>,
    authority_id: [u8; 16],
    epoch: u64,
    current_epoch: Arc<std::sync::atomic::AtomicU64>,
    prohibited_content: Arc<dyn ProhibitedContentPort>,
    #[cfg(feature = "desktop-protected")]
    root_admission: super::root_handle_admission::RootAdmissionGateway,
    #[cfg(all(feature = "desktop-protected", target_os = "linux"))] permission_admission: Option<
        Arc<runne_platform::local_command_linux::LinuxCompositeScopeAdmission>,
    >,
    #[cfg(target_os = "linux")] _node_lease_heartbeat: Arc<
        dyn Fn() -> Result<(), ()> + Send + Sync,
    >,
) -> Result<Arc<dyn runne_runtime::taskrun_auto_worker::AutomaticTaskRunService>, DaemonError> {
    #[cfg(feature = "desktop-protected")]
    {
        let _ = prohibited_content;
        super::exec_taskrun_recovery::automatic_taskrun_service_with_root(
            super::exec_taskrun_worker::ProtectedTaskRunWorkerConfig {
                store: store.clone(),
                taskruns: service,
                #[cfg(target_os = "linux")]
                tool_loop_service: super::tool_loop_service(
                    store.clone(),
                    RuntimeAuthorityId(hex::encode(authority_id)),
                    provider.clone(),
                    root_admission.clone(),
                ),
                text,
                provider,
                node_id: runne_application::ports::ExecutionNodeId(
                    uuid::Uuid::from_bytes(authority_id).to_string(),
                ),
                epoch,
                current_epoch,
                #[cfg(target_os = "linux")]
                root_admission,
                #[cfg(target_os = "linux")]
                permission_admission,
                #[cfg(target_os = "linux")]
                node_lease_heartbeat: _node_lease_heartbeat,
            },
        )
    }
    #[cfg(not(feature = "desktop-protected"))]
    {
        let _ = prohibited_content;
        super::exec_taskrun_recovery::automatic_taskrun_service(
            store,
            service,
            text,
            provider,
            authority_id,
            epoch,
            current_epoch,
        )
    }
}
