pub struct AppCore {
    store: Mutex<LocalStore>,
    mutation_security: Option<MutationSecurityContext>,
    runtime_mode: RuntimeMode,
    runtime_profile_path: Option<PathBuf>,
    runtime_state: RwLock<RuntimeAvailability>,
    host_lifecycle: RwLock<HostLifecycleState>,
    lifecycle_sender: tokio::sync::mpsc::Sender<HostLifecycleEventV1>,
    lifecycle_event_pipeline: Mutex<HostLifecycleEventPipeline>,
    lifecycle_pipeline_closed: AtomicBool,
    lifecycle_producer_drops: AtomicU64,
    lifecycle_producer_drop_saturated: AtomicBool,
    lifecycle_evictions: AtomicU64,
    lifecycle_eviction_saturated: AtomicBool,
    bundled_activation_epoch: Mutex<u64>,
    pending_resync_scopes: RwLock<HashSet<ReplayScopeKey>>,
    runtime_client: RwLock<Option<AuthenticatedRuntimeClient>>,
    runtime_connect: tokio::sync::Mutex<()>,
    runtime_operation: tokio::sync::Mutex<()>,
    mutation_gate_epoch: AtomicU64,
    #[cfg(any(test, feature = "test-support"))]
    mutation_test_hold_before_canonical: AtomicBool,
    #[cfg(any(test, feature = "test-support"))]
    mutation_test_before_canonical_reached: tokio::sync::Notify,
    #[cfg(any(test, feature = "test-support"))]
    mutation_test_continue_canonical: tokio::sync::Notify,
    #[cfg(any(test, feature = "test-support"))]
    mutation_test_hold_before_dispatch: AtomicBool,
    #[cfg(any(test, feature = "test-support"))]
    mutation_test_before_dispatch: tokio::sync::Notify,
}

struct MutationSecurityContext {
    secure: Arc<dyn SecureStore>,
}

#[derive(Clone)]
struct RuntimeOperationContext {
    client: AuthenticatedRuntimeClient,
    gate_epoch: u64,
    identity: replay::StableRuntimeIdentity,
}
