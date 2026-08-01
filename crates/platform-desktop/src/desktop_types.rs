/// Maximum time the desktop waits for a proven owned runtime to stop cleanly.
pub const BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Closed lifecycle states for a desktop-owned bundled runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundledRuntimeLifecycleState {
    Absent,
    ValidatingBinary,
    Spawning,
    Handshaking,
    Ready,
    FailedStart,
    Disconnected,
    Probing,
    Crashed,
    Backoff,
    Exhausted,
    Stopping,
    Stopped,
    Incompatible,
    IdentityMismatch,
    OwnershipConflict,
}

/// Launch mode accepted by the bundled-runtime supervisor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundledRuntimeLaunchMode {
    Direct,
    Shell,
}

/// Prohibited locations for a bundled-runtime launch secret.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundledRuntimeSecretTransport {
    Environment,
    Arguments,
    File,
    Stdout,
    InheritedPipeOrHandle,
}

/// Typed rejection for an unsafe bundled-runtime launch request.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BundledRuntimeLaunchError {
    #[error("bundled runtime executable path must be absolute")]
    ExecutablePathNotAbsolute,
    #[error("bundled runtime launch must not use a shell")]
    ShellForbidden,
    #[error("bundled runtime launch-secret transport is not available")]
    SecretTransportUnsupported,
}

/// A validated, direct bundled-runtime launch request.
///
/// This is the Slice 2A generic supervision test contract. It contains no
/// runnable protected authority and has no concrete system launcher. Production
/// desktop activation uses [`ProtectedBundledRuntimeLaunchSpec`] and
/// [`DevelopmentBundledRuntimeLauncher`].
#[derive(Clone, Eq, PartialEq)]
pub struct BundledRuntimeLaunchSpec {
    executable: PathBuf,
    profile_binding: Option<BundledRuntimeProfileBinding>,
}

impl fmt::Debug for BundledRuntimeLaunchSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BundledRuntimeLaunchSpec")
            .field("executable", &"<redacted>")
            .field("profile_binding", &self.profile_binding.is_some())
            .finish()
    }
}

impl BundledRuntimeLaunchSpec {
    /// Validates the fail-closed launch policy before process spawning exists.
    ///
    /// # Errors
    ///
    /// Rejects relative executables, shell launches, and every launch-secret
    /// transport because this legacy shape cannot carry the protected binding.
    pub fn new(
        executable: PathBuf,
        mode: BundledRuntimeLaunchMode,
        secret_transport: Option<BundledRuntimeSecretTransport>,
    ) -> Result<Self, BundledRuntimeLaunchError> {
        if !executable.is_absolute() {
            return Err(BundledRuntimeLaunchError::ExecutablePathNotAbsolute);
        }
        if mode == BundledRuntimeLaunchMode::Shell {
            return Err(BundledRuntimeLaunchError::ShellForbidden);
        }
        if secret_transport.is_some() {
            return Err(BundledRuntimeLaunchError::SecretTransportUnsupported);
        }
        Ok(Self {
            executable,
            profile_binding: None,
        })
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }

    /// Attaches an opaque profile binding prepared by the protected launch path.
    #[must_use]
    pub fn with_profile_binding(mut self, profile_binding: BundledRuntimeProfileBinding) -> Self {
        self.profile_binding = Some(profile_binding);
        self
    }
}

/// The next action after an unexpected bundled-runtime exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundledRuntimeRestartDisposition {
    RestartAfter(Duration),
    Exhausted,
}

/// Closed result of polling a desktop-owned bundled process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundledRuntimeProcessStatus {
    Running,
    Exited,
}

/// Opaque expected Secure Replay v2 profile identity for one bundled launch.
#[derive(Clone, Eq, PartialEq)]
pub struct BundledRuntimeProfileBinding {
    identity: BundledRuntimeAuthenticatedIdentity,
}

/// Renderer-invisible identity returned by an authenticated Secure Replay v2
/// profile/session handshake.
#[derive(Clone, Eq, PartialEq)]
pub struct BundledRuntimeAuthenticatedIdentity {
    profile_id: String,
    schema_hash: String,
    authority_id: String,
    principal_id: String,
    event_log_lineage_id: String,
    daemon_instance_id: String,
    launch_generation: u64,
    capability_digest: String,
    certificate_sha256: String,
    session_id: String,
}

impl BundledRuntimeProfileBinding {
    #[cfg(test)]
    fn for_test(identity: &BundledRuntimeAuthenticatedIdentity) -> Self {
        Self {
            identity: identity.clone(),
        }
    }

    fn matches(&self, identity: &BundledRuntimeAuthenticatedIdentity) -> bool {
        self.identity == *identity
    }
}

/// Authenticated Secure Replay v2 result for one owned bundled launch.
///
/// Construction is intentionally reserved for the Secure Replay integration;
/// callers cannot synthesize a ready transition from a profile path, PID or
/// diagnostic stdout.
#[derive(Clone, Eq, PartialEq)]
pub struct BundledRuntimeAuthenticatedHandshake {
    identity: BundledRuntimeAuthenticatedIdentity,
}

impl BundledRuntimeAuthenticatedHandshake {
    #[cfg(test)]
    const fn for_test(identity: BundledRuntimeAuthenticatedIdentity) -> Self {
        Self { identity }
    }
}

/// Host process capability used by the bundled-runtime supervisor.
///
/// The process object is deliberately opaque: its PID is not an ownership
/// proof and is not exposed by this contract.
pub trait BundledRuntimeProcess {
    /// Polls the process without blocking the desktop event loop.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error if the child status cannot be read.
    fn status(&mut self) -> std::io::Result<BundledRuntimeProcessStatus>;

    /// Requests an orderly runtime shutdown through the owned control path.
    ///
    /// This must not claim that active runtime work was cancelled. The runtime
    /// event log remains authoritative for recovery of work that did not
    /// complete before the process exits.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the protected shutdown control
    /// cannot deliver the orderly-stop request.
    fn request_graceful_stop(&mut self) -> std::io::Result<()>;

    /// Waits at most `timeout` for the owned process to exit after an orderly
    /// shutdown request.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when the process status cannot be
    /// observed during the wait.
    fn wait_for_exit(&mut self, timeout: Duration) -> std::io::Result<BundledRuntimeProcessStatus>;

    /// Terminates the process tree represented by this already-owned handle.
    ///
    /// # Errors
    ///
    /// Returns an operating-system error when termination cannot be requested.
    fn terminate(&mut self) -> std::io::Result<()>;
}

/// Direct, host-owned process launcher used by the bundled-runtime supervisor.
pub trait BundledRuntimeProcessLauncher {
    type Process: BundledRuntimeProcess;

    /// Spawns the already validated absolute executable without a shell.
    ///
    /// # Errors
    ///
    /// Returns the operating-system error if the direct process launch fails.
    fn launch(&mut self, spec: &BundledRuntimeLaunchSpec) -> std::io::Result<Self::Process>;
}

/// Time source for deterministic bundled-runtime supervision.
pub trait BundledRuntimeClock {
    /// Returns the current monotonic instant.
    fn now(&self) -> Instant;
}

/// Production monotonic clock for bundled-runtime supervision.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemBundledRuntimeClock;

impl BundledRuntimeClock for SystemBundledRuntimeClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Typed supervision failure that does not expose protected launch details.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum BundledRuntimeSupervisorError {
    #[error("bundled runtime process could not be started")]
    SpawnFailed,
    #[error("bundled runtime process status is unavailable")]
    ProcessStatusUnavailable,
    #[error("bundled runtime is already running")]
    AlreadyRunning,
    #[error("bundled runtime cannot be started from its current lifecycle state")]
    InvalidStartState,
    #[error("bundled runtime authenticated handshake does not match the current launch")]
    HandshakeMismatch,
    #[error("bundled runtime launch profile binding is unavailable")]
    ProfileBindingUnavailable,
    #[error("bundled runtime shutdown ownership does not match the current launch")]
    ShutdownOwnershipMismatch,
    #[error("bundled runtime graceful shutdown is unavailable")]
    GracefulStopUnavailable,
    #[error("bundled runtime forced termination is unavailable")]
    ForcedStopUnavailable,
    #[error("bundled runtime forced termination was not confirmed")]
    ForcedStopUnconfirmed,
}

/// Closed result of stopping a proven desktop-owned bundled runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundledRuntimeStopDisposition {
    Graceful,
    Forced,
}
