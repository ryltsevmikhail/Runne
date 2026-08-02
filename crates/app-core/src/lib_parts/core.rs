pub struct AppCore {
    store: Mutex<LocalStore>,
    runtime_mode: RuntimeMode,
    runtime_profile_path: Option<PathBuf>,
    runtime_state: RwLock<RuntimeAvailability>,
    runtime_lifecycle: RwLock<RuntimeLifecycleStatus>,
    runtime_failure: RwLock<Option<RuntimeFailureCode>>,
    bundled_activation_epoch: Mutex<u64>,
    pending_resync_scopes: RwLock<HashSet<ReplayScopeKey>>,
    runtime_client: RwLock<Option<AuthenticatedRuntimeClient>>,
    runtime_connect: tokio::sync::Mutex<()>,
    runtime_operation: tokio::sync::Mutex<()>,
}
