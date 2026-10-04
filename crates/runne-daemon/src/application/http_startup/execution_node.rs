use super::super::execution_node_lifecycle::LinuxExecutionNode;
use super::super::{BootstrapOutcome, DaemonError, RuntimeSessionBinding, StoreTransaction};
use runne_application::local_session::LocalSessionService;
use std::sync::{Arc, Mutex, atomic::AtomicU64};

pub(super) struct RegisteredExecutionNode {
    pub(super) worker_epoch: Arc<AtomicU64>,
    pub(super) node: LinuxExecutionNode,
    pub(super) heartbeat: Arc<dyn Fn() -> Result<(), ()> + Send + Sync>,
}

pub(super) fn register_before_taskrun_recovery(
    store: &StoreTransaction,
    sessions: &Arc<Mutex<LocalSessionService>>,
    bootstrap: &BootstrapOutcome,
    binding: &RuntimeSessionBinding,
) -> Result<RegisteredExecutionNode, DaemonError> {
    let worker_epoch = Arc::new(AtomicU64::new(bootstrap.launch_generation));
    let mut node = LinuxExecutionNode::with_worker_epoch(
        bootstrap.authority_id,
        bootstrap.local_session_authority_id,
        binding.ephemeral().daemon_instance_id().into_bytes(),
        bootstrap.launch_generation,
        Arc::clone(&worker_epoch),
    );
    node.register(store, sessions)?;
    let authority_id = bootstrap.authority_id;
    let local_session_authority_id = bootstrap.local_session_authority_id;
    let daemon_instance_id = binding.ephemeral().daemon_instance_id().into_bytes();
    let expected_generation = bootstrap.launch_generation;
    let lease_store = store.clone();
    let lease_sessions = Arc::clone(sessions);
    let heartbeat = Arc::new(move || {
        super::super::execution_node_lifecycle::heartbeat_recovery_lease(
            &lease_store,
            &lease_sessions,
            authority_id,
            local_session_authority_id,
            daemon_instance_id,
            expected_generation,
        )
        .map_err(|_| ())
    });
    Ok(RegisteredExecutionNode {
        worker_epoch,
        node,
        heartbeat,
    })
}
