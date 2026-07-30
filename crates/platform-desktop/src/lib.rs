//! Desktop implementations of native capability ports.

use std::collections::VecDeque;
use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use gocode_runtime_client::RuntimeSessionInfo;
use thiserror::Error;

const MINIMUM_WINDOW_WIDTH: i32 = 960;
const MINIMUM_WINDOW_HEIGHT: i32 = 600;
const DEFAULT_WINDOW_WIDTH: i32 = 1_440;
const DEFAULT_WINDOW_HEIGHT: i32 = 900;
const BACKOFF_DELAYS: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(30),
];
const UNEXPECTED_EXIT_WINDOW: Duration = Duration::from_mins(10);

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
/// The spec deliberately contains neither environment nor argument data. Those
/// channels cannot carry a launch secret, and protected inherited
/// pipe/handle support is not available in this slice.
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
    /// transport until a protected inherited pipe/handle implementation exists.
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
    fn for_test(session: &RuntimeSessionInfo) -> Self {
        Self {
            profile_id: session.profile_id.clone(),
            schema_hash: session.schema_hash.clone(),
            authority_id: session.authority_id.clone(),
            principal_id: session.principal_id.clone(),
            event_log_lineage_id: session.event_log_lineage_id.clone(),
            daemon_instance_id: session.daemon_instance_id.clone(),
            launch_generation: session.launch_generation,
            capability_digest: session.capability_digest.clone(),
            certificate_sha256: session.certificate_sha256.clone(),
            session_id: session.session_id.clone(),
        }
    }

    fn matches(&self, session: &RuntimeSessionInfo) -> bool {
        self.profile_id == session.profile_id
            && self.schema_hash == session.schema_hash
            && self.authority_id == session.authority_id
            && self.principal_id == session.principal_id
            && self.event_log_lineage_id == session.event_log_lineage_id
            && self.daemon_instance_id == session.daemon_instance_id
            && self.launch_generation == session.launch_generation
            && self.capability_digest == session.capability_digest
            && self.certificate_sha256 == session.certificate_sha256
            && self.session_id == session.session_id
    }
}

/// Authenticated Secure Replay v2 result for one owned bundled launch.
///
/// Construction is intentionally reserved for the Secure Replay integration;
/// callers cannot synthesize a ready transition from a profile path, PID or
/// diagnostic stdout.
#[derive(Clone, Eq, PartialEq)]
pub struct BundledRuntimeAuthenticatedHandshake {
    session: RuntimeSessionInfo,
}

impl BundledRuntimeAuthenticatedHandshake {
    #[cfg(test)]
    const fn for_test(session: RuntimeSessionInfo) -> Self {
        Self { session }
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

/// Production direct launcher for a bundled runtime development profile.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemBundledRuntimeProcessLauncher;

/// Opaque child process owned by the launcher that created it.
#[derive(Debug)]
pub struct SystemBundledRuntimeProcess {
    child: Child,
}

impl BundledRuntimeProcessLauncher for SystemBundledRuntimeProcessLauncher {
    type Process = SystemBundledRuntimeProcess;

    fn launch(&mut self, spec: &BundledRuntimeLaunchSpec) -> std::io::Result<Self::Process> {
        let child = Command::new(spec.executable())
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(SystemBundledRuntimeProcess { child })
    }
}

impl BundledRuntimeProcess for SystemBundledRuntimeProcess {
    fn status(&mut self) -> std::io::Result<BundledRuntimeProcessStatus> {
        self.child.try_wait().map(|status| {
            if status.is_some() {
                BundledRuntimeProcessStatus::Exited
            } else {
                BundledRuntimeProcessStatus::Running
            }
        })
    }

    fn request_graceful_stop(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "protected bundled runtime shutdown control is unavailable",
        ))
    }

    fn wait_for_exit(&mut self, timeout: Duration) -> std::io::Result<BundledRuntimeProcessStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.status()? == BundledRuntimeProcessStatus::Exited || Instant::now() >= deadline {
                return self.status();
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn terminate(&mut self) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "protected bundled runtime process-tree termination is unavailable",
        ))
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

/// Host-side supervisor for a single desktop-owned bundled runtime process.
///
/// Authenticated readiness is deliberately reported by the Secure Replay v2
/// profile/session handshake; process stdout cannot mark this supervisor ready.
pub struct BundledRuntimeSupervisor<L, C>
where
    L: BundledRuntimeProcessLauncher,
    C: BundledRuntimeClock,
{
    launcher: L,
    clock: C,
    spec: BundledRuntimeLaunchSpec,
    process: Option<L::Process>,
    profile_binding: Option<BundledRuntimeProfileBinding>,
    backoff: BundledRuntimeBackoff,
    restart_at: Option<Instant>,
    state: BundledRuntimeLifecycleState,
}

impl<L, C> BundledRuntimeSupervisor<L, C>
where
    L: BundledRuntimeProcessLauncher,
    C: BundledRuntimeClock,
{
    #[must_use]
    pub fn new(launcher: L, clock: C, spec: BundledRuntimeLaunchSpec) -> Self {
        Self {
            launcher,
            clock,
            spec,
            process: None,
            profile_binding: None,
            backoff: BundledRuntimeBackoff::new(),
            restart_at: None,
            state: BundledRuntimeLifecycleState::Absent,
        }
    }

    #[must_use]
    pub const fn state(&self) -> BundledRuntimeLifecycleState {
        self.state
    }

    /// Starts the direct bundled executable and waits for an authenticated
    /// Secure Replay v2 readiness callback before becoming ready.
    ///
    /// # Errors
    ///
    /// Returns a typed redacted failure if spawning fails.
    pub fn start(&mut self) -> Result<(), BundledRuntimeSupervisorError> {
        match self.state {
            BundledRuntimeLifecycleState::Absent | BundledRuntimeLifecycleState::FailedStart => {}
            BundledRuntimeLifecycleState::Handshaking | BundledRuntimeLifecycleState::Ready => {
                return Err(BundledRuntimeSupervisorError::AlreadyRunning);
            }
            _ => return Err(BundledRuntimeSupervisorError::InvalidStartState),
        }
        self.spawn_process()
    }

    fn spawn_process(&mut self) -> Result<(), BundledRuntimeSupervisorError> {
        let Some(profile_binding) = self.spec.profile_binding.take() else {
            self.state = BundledRuntimeLifecycleState::FailedStart;
            return Err(BundledRuntimeSupervisorError::ProfileBindingUnavailable);
        };
        self.state = BundledRuntimeLifecycleState::ValidatingBinary;
        self.state = BundledRuntimeLifecycleState::Spawning;
        let Ok(process) = self.launcher.launch(&self.spec) else {
            self.restart_at = None;
            self.state = BundledRuntimeLifecycleState::FailedStart;
            return Err(BundledRuntimeSupervisorError::SpawnFailed);
        };
        self.process = Some(process);
        self.profile_binding = Some(profile_binding);
        self.restart_at = None;
        self.state = BundledRuntimeLifecycleState::Handshaking;
        Ok(())
    }

    /// Accepts readiness only after the authenticated Secure Replay v2
    /// profile/session handshake has completed for this launch.
    ///
    /// # Errors
    ///
    /// Returns a typed mismatch when the authenticated session does not prove
    /// the expected current Secure Replay v2 profile binding.
    pub fn record_authenticated_ready(
        &mut self,
        handshake: &BundledRuntimeAuthenticatedHandshake,
    ) -> Result<(), BundledRuntimeSupervisorError> {
        let Some(binding) = self.profile_binding.as_ref() else {
            return Err(BundledRuntimeSupervisorError::HandshakeMismatch);
        };
        if self.process.is_none()
            || self.state != BundledRuntimeLifecycleState::Handshaking
            || !binding.matches(&handshake.session)
        {
            return Err(BundledRuntimeSupervisorError::HandshakeMismatch);
        }
        self.backoff.record_authenticated_ready(self.clock.now());
        self.state = BundledRuntimeLifecycleState::Ready;
        Ok(())
    }

    /// Fences new supervision work and stops the exact launch proved by the
    /// current Secure Replay v2 session identity.
    ///
    /// A stale handshake cannot stop a replacement launch. If the orderly stop
    /// does not finish within `timeout`, only the process represented by the
    /// existing owned handle is terminated.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when ownership is stale or the owned process
    /// cannot be stopped. It never reports `TaskRun` cancellation success.
    pub fn stop(
        &mut self,
        handshake: &BundledRuntimeAuthenticatedHandshake,
        timeout: Duration,
    ) -> Result<BundledRuntimeStopDisposition, BundledRuntimeSupervisorError> {
        let ownership_matches = self
            .profile_binding
            .as_ref()
            .is_some_and(|binding| binding.matches(&handshake.session));
        if self.state != BundledRuntimeLifecycleState::Ready
            || self.process.is_none()
            || !ownership_matches
        {
            return Err(BundledRuntimeSupervisorError::ShutdownOwnershipMismatch);
        }

        self.state = BundledRuntimeLifecycleState::Stopping;
        self.restart_at = None;
        self.backoff.record_disconnected();
        let stop_status = {
            let Some(process) = self.process.as_mut() else {
                return Err(BundledRuntimeSupervisorError::ShutdownOwnershipMismatch);
            };
            if process.request_graceful_stop().is_err() {
                self.state = BundledRuntimeLifecycleState::Ready;
                return Err(BundledRuntimeSupervisorError::GracefulStopUnavailable);
            }
            if let Ok(status) = process.wait_for_exit(timeout) {
                status
            } else {
                self.state = BundledRuntimeLifecycleState::Ready;
                return Err(BundledRuntimeSupervisorError::ProcessStatusUnavailable);
            }
        };
        if stop_status == BundledRuntimeProcessStatus::Exited {
            self.process = None;
            self.profile_binding = None;
            self.state = BundledRuntimeLifecycleState::Stopped;
            return Ok(BundledRuntimeStopDisposition::Graceful);
        }
        let Some(process) = self.process.as_mut() else {
            return Err(BundledRuntimeSupervisorError::ShutdownOwnershipMismatch);
        };
        process
            .terminate()
            .map_err(|_| BundledRuntimeSupervisorError::ForcedStopUnavailable)?;
        match process.wait_for_exit(timeout) {
            Ok(BundledRuntimeProcessStatus::Exited) => {
                self.process = None;
                self.profile_binding = None;
                self.state = BundledRuntimeLifecycleState::Stopped;
                Ok(BundledRuntimeStopDisposition::Forced)
            }
            Ok(BundledRuntimeProcessStatus::Running) => {
                Err(BundledRuntimeSupervisorError::ForcedStopUnconfirmed)
            }
            Err(_) => Err(BundledRuntimeSupervisorError::ForcedStopUnconfirmed),
        }
    }

    /// Polls the owned child and performs a due bounded restart.
    ///
    /// # Errors
    ///
    /// Returns a typed redacted failure if the process status cannot be read or
    /// a scheduled restart cannot be spawned.
    pub fn monitor(&mut self) -> Result<(), BundledRuntimeSupervisorError> {
        if self.state == BundledRuntimeLifecycleState::Stopped {
            return Ok(());
        }
        if self.state == BundledRuntimeLifecycleState::Stopping {
            let Some(process) = self.process.as_mut() else {
                return Err(BundledRuntimeSupervisorError::ProcessStatusUnavailable);
            };
            if process
                .status()
                .map_err(|_| BundledRuntimeSupervisorError::ProcessStatusUnavailable)?
                == BundledRuntimeProcessStatus::Exited
            {
                self.process = None;
                self.profile_binding = None;
                self.state = BundledRuntimeLifecycleState::Stopped;
            }
            return Ok(());
        }
        let now = self.clock.now();
        if self.state == BundledRuntimeLifecycleState::Ready {
            self.backoff.reset_after_stable_readiness(now);
        }

        if self.state == BundledRuntimeLifecycleState::Backoff
            && self.restart_at.is_some_and(|restart_at| now >= restart_at)
        {
            self.spawn_process()?;
            return Ok(());
        }

        let Some(process) = self.process.as_mut() else {
            return Ok(());
        };
        if process
            .status()
            .map_err(|_| BundledRuntimeSupervisorError::ProcessStatusUnavailable)?
            == BundledRuntimeProcessStatus::Exited
        {
            self.process = None;
            self.profile_binding = None;
            self.state = BundledRuntimeLifecycleState::Crashed;
            match self.backoff.record_unexpected_exit(now) {
                BundledRuntimeRestartDisposition::RestartAfter(delay) => {
                    self.restart_at = Some(now + delay);
                    self.state = BundledRuntimeLifecycleState::Backoff;
                }
                BundledRuntimeRestartDisposition::Exhausted => {
                    self.restart_at = None;
                    self.state = BundledRuntimeLifecycleState::Exhausted;
                }
            }
        }
        Ok(())
    }
}

/// Bounded restart budget for a desktop-owned bundled runtime.
#[derive(Debug, Default)]
pub struct BundledRuntimeBackoff {
    unexpected_exits: VecDeque<Instant>,
    authenticated_ready_since: Option<Instant>,
}

impl BundledRuntimeBackoff {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an unexpected exit and returns the bounded restart action.
    #[must_use]
    pub fn record_unexpected_exit(&mut self, now: Instant) -> BundledRuntimeRestartDisposition {
        self.record_disconnected();
        self.prune_expired(now);
        if self.unexpected_exits.len() == BACKOFF_DELAYS.len() {
            return BundledRuntimeRestartDisposition::Exhausted;
        }

        let delay = BACKOFF_DELAYS[self.unexpected_exits.len()];
        self.unexpected_exits.push_back(now);
        BundledRuntimeRestartDisposition::RestartAfter(delay)
    }

    /// Starts the stable-readiness interval after an authenticated handshake.
    pub fn record_authenticated_ready(&mut self, now: Instant) {
        self.authenticated_ready_since.get_or_insert(now);
    }

    /// Invalidates authenticated readiness after a disconnect or crash.
    pub const fn record_disconnected(&mut self) {
        self.authenticated_ready_since = None;
    }

    /// Resets the exit budget only after ten continuous authenticated-ready minutes.
    pub fn reset_after_stable_readiness(&mut self, now: Instant) -> bool {
        if self
            .authenticated_ready_since
            .and_then(|ready_at| now.checked_duration_since(ready_at))
            .is_some_and(|elapsed| elapsed >= UNEXPECTED_EXIT_WINDOW)
        {
            self.unexpected_exits.clear();
            return true;
        }
        false
    }

    fn prune_expired(&mut self, now: Instant) {
        while self.unexpected_exits.front().is_some_and(|exit| {
            now.checked_duration_since(*exit)
                .is_some_and(|elapsed| elapsed >= UNEXPECTED_EXIT_WINDOW)
        }) {
            self.unexpected_exits.pop_front();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowGeometry {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayWorkArea {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// Validates persisted geometry against the currently attached display.
///
/// Invalid dimensions fall back to the documented initial size. All returned
/// bounds are contained by the supplied work area.
#[must_use]
pub fn restore_window_geometry(
    stored: WindowGeometry,
    work_area: DisplayWorkArea,
) -> WindowGeometry {
    let valid_stored = stored.width >= MINIMUM_WINDOW_WIDTH
        && stored.height >= MINIMUM_WINDOW_HEIGHT
        && work_area.width >= MINIMUM_WINDOW_WIDTH
        && work_area.height >= MINIMUM_WINDOW_HEIGHT;
    let (requested_width, requested_height) = if valid_stored {
        (stored.width, stored.height)
    } else {
        (DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT)
    };
    let width = requested_width.min(work_area.width).max(1);
    let height = requested_height.min(work_area.height).max(1);
    let default_x = work_area.x + (work_area.width - width) / 2;
    let default_y = work_area.y + (work_area.height - height) / 2;
    let requested_x = if valid_stored { stored.x } else { default_x };
    let requested_y = if valid_stored { stored.y } else { default_y };
    let maximum_x = work_area.x + work_area.width - width;
    let maximum_y = work_area.y + work_area.height - height;

    WindowGeometry {
        x: requested_x.clamp(work_area.x, maximum_x),
        y: requested_y.clamp(work_area.y, maximum_y),
        width,
        height,
    }
}

#[derive(Debug, Error)]
pub enum ProfileLockError {
    #[error("profile is already owned")]
    AlreadyOwned,
    #[error("profile lock unavailable")]
    Unavailable(#[source] std::io::Error),
}

#[derive(Debug)]
pub struct ProfileLock {
    _file: File,
}

impl ProfileLock {
    /// Acquires the operating-system lock for one application profile.
    ///
    /// The lock is released automatically when the owning process exits.
    ///
    /// # Errors
    ///
    /// Returns a typed ownership conflict or a filesystem error.
    pub fn acquire(path: &Path) -> Result<Self, ProfileLockError> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .map_err(ProfileLockError::Unavailable)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(TryLockError::WouldBlock) => Err(ProfileLockError::AlreadyOwned),
            Err(TryLockError::Error(error)) => Err(ProfileLockError::Unavailable(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    use super::{
        BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT, BundledRuntimeAuthenticatedHandshake,
        BundledRuntimeBackoff, BundledRuntimeClock, BundledRuntimeLaunchError,
        BundledRuntimeLaunchMode, BundledRuntimeLaunchSpec, BundledRuntimeLifecycleState,
        BundledRuntimeProcess, BundledRuntimeProcessLauncher, BundledRuntimeProcessStatus,
        BundledRuntimeProfileBinding, BundledRuntimeRestartDisposition,
        BundledRuntimeSecretTransport, BundledRuntimeStopDisposition, BundledRuntimeSupervisor,
        BundledRuntimeSupervisorError, DisplayWorkArea, ProfileLock, UNEXPECTED_EXIT_WINDOW,
        WindowGeometry, restore_window_geometry,
    };
    use gocode_runtime_client::RuntimeSessionInfo;

    #[derive(Clone)]
    struct FakeClock(Rc<Cell<Instant>>);

    impl FakeClock {
        fn new(now: Instant) -> Self {
            Self(Rc::new(Cell::new(now)))
        }

        fn advance(&self, duration: Duration) {
            self.0.set(self.0.get() + duration);
        }
    }

    impl BundledRuntimeClock for FakeClock {
        fn now(&self) -> Instant {
            self.0.get()
        }
    }

    struct FakeProcess {
        statuses: VecDeque<BundledRuntimeProcessStatus>,
        graceful_stop_requests: Rc<Cell<u32>>,
        termination_requests: Rc<Cell<u32>>,
        graceful_stop_fails: bool,
        wait_fails: bool,
    }

    impl FakeProcess {
        fn with_statuses(statuses: impl IntoIterator<Item = BundledRuntimeProcessStatus>) -> Self {
            Self {
                statuses: statuses.into_iter().collect(),
                graceful_stop_requests: Rc::new(Cell::new(0)),
                termination_requests: Rc::new(Cell::new(0)),
                graceful_stop_fails: false,
                wait_fails: false,
            }
        }

        fn running() -> Self {
            Self::with_statuses([BundledRuntimeProcessStatus::Running])
        }

        fn exited() -> Self {
            Self::with_statuses([BundledRuntimeProcessStatus::Exited])
        }

        fn with_stop_tracking(
            statuses: impl IntoIterator<Item = BundledRuntimeProcessStatus>,
        ) -> (Self, Rc<Cell<u32>>, Rc<Cell<u32>>) {
            let graceful_stop_requests = Rc::new(Cell::new(0));
            let termination_requests = Rc::new(Cell::new(0));
            (
                Self {
                    statuses: statuses.into_iter().collect(),
                    graceful_stop_requests: Rc::clone(&graceful_stop_requests),
                    termination_requests: Rc::clone(&termination_requests),
                    graceful_stop_fails: false,
                    wait_fails: false,
                },
                graceful_stop_requests,
                termination_requests,
            )
        }

        fn with_stop_failures(graceful_stop_fails: bool, wait_fails: bool) -> Self {
            Self {
                statuses: VecDeque::new(),
                graceful_stop_requests: Rc::new(Cell::new(0)),
                termination_requests: Rc::new(Cell::new(0)),
                graceful_stop_fails,
                wait_fails,
            }
        }
    }

    impl BundledRuntimeProcess for FakeProcess {
        fn status(&mut self) -> io::Result<BundledRuntimeProcessStatus> {
            Ok(self
                .statuses
                .pop_front()
                .unwrap_or(BundledRuntimeProcessStatus::Running))
        }

        fn request_graceful_stop(&mut self) -> io::Result<()> {
            self.graceful_stop_requests
                .set(self.graceful_stop_requests.get() + 1);
            if self.graceful_stop_fails {
                return Err(io::Error::other("graceful stop failure"));
            }
            Ok(())
        }

        fn wait_for_exit(&mut self, _timeout: Duration) -> io::Result<BundledRuntimeProcessStatus> {
            if self.wait_fails {
                return Err(io::Error::other("wait failure"));
            }
            self.status()
        }

        fn terminate(&mut self) -> io::Result<()> {
            self.termination_requests
                .set(self.termination_requests.get() + 1);
            Ok(())
        }
    }

    struct FakeLauncher {
        launches: Rc<Cell<u32>>,
        results: VecDeque<Result<FakeProcess, ()>>,
    }

    impl FakeLauncher {
        fn new(
            results: impl IntoIterator<Item = Result<FakeProcess, ()>>,
        ) -> (Self, Rc<Cell<u32>>) {
            let launches = Rc::new(Cell::new(0));
            (
                Self {
                    launches: Rc::clone(&launches),
                    results: results.into_iter().collect(),
                },
                launches,
            )
        }
    }

    impl BundledRuntimeProcessLauncher for FakeLauncher {
        type Process = FakeProcess;

        fn launch(&mut self, _spec: &BundledRuntimeLaunchSpec) -> io::Result<Self::Process> {
            self.launches.set(self.launches.get() + 1);
            self.results
                .pop_front()
                .unwrap_or(Err(()))
                .map_err(|()| io::Error::other("fake spawn failure"))
        }
    }

    fn launch_spec() -> BundledRuntimeLaunchSpec {
        BundledRuntimeLaunchSpec::new(
            PathBuf::from("/opt/gocode/gocoded"),
            BundledRuntimeLaunchMode::Direct,
            None,
        )
        .expect("valid launch spec")
        .with_profile_binding(BundledRuntimeProfileBinding::for_test(&runtime_session()))
    }

    fn runtime_session() -> RuntimeSessionInfo {
        RuntimeSessionInfo {
            profile_id: "gocode-ui-client/1".to_owned(),
            schema_hash: "a".repeat(64),
            runtime_version: "0.1.0".to_owned(),
            capabilities: vec!["conversation.read".to_owned()],
            authority_id: "0".repeat(32),
            principal_id: "desktop-development".to_owned(),
            event_log_lineage_id: "0199d55d-1a23-7000-8000-000000000001".to_owned(),
            daemon_instance_id: "0199d55d-1a23-7000-8000-000000000002".to_owned(),
            launch_generation: 1,
            session_id: "1".repeat(32),
            authorization_epoch: 0,
            sensitivity_ceiling: "sensitive".to_owned(),
            certificate_sha256: "b".repeat(64),
            capability_digest: "c".repeat(64),
        }
    }

    fn authenticated_handshake() -> BundledRuntimeAuthenticatedHandshake {
        BundledRuntimeAuthenticatedHandshake::for_test(runtime_session())
    }

    fn prepare_next_profile_binding(
        supervisor: &mut BundledRuntimeSupervisor<FakeLauncher, FakeClock>,
        session: &RuntimeSessionInfo,
    ) {
        supervisor.spec.profile_binding = Some(BundledRuntimeProfileBinding::for_test(session));
    }

    #[test]
    fn bundled_runtime_launch_spec_requires_an_absolute_direct_non_secret_launch() {
        assert_eq!(
            BundledRuntimeLaunchSpec::new(
                PathBuf::from("gocoded"),
                BundledRuntimeLaunchMode::Direct,
                None,
            ),
            Err(BundledRuntimeLaunchError::ExecutablePathNotAbsolute)
        );
        assert_eq!(
            BundledRuntimeLaunchSpec::new(
                PathBuf::from("/opt/gocode/gocoded"),
                BundledRuntimeLaunchMode::Shell,
                None,
            ),
            Err(BundledRuntimeLaunchError::ShellForbidden)
        );

        let spec = BundledRuntimeLaunchSpec::new(
            PathBuf::from("/opt/gocode/gocoded"),
            BundledRuntimeLaunchMode::Direct,
            None,
        )
        .expect("accept direct launch without a secret transport");
        assert_eq!(
            spec.executable(),
            std::path::Path::new("/opt/gocode/gocoded")
        );
    }

    #[test]
    fn bundled_runtime_launch_spec_fails_closed_for_every_secret_transport() {
        for transport in [
            BundledRuntimeSecretTransport::Environment,
            BundledRuntimeSecretTransport::Arguments,
            BundledRuntimeSecretTransport::File,
            BundledRuntimeSecretTransport::Stdout,
            BundledRuntimeSecretTransport::InheritedPipeOrHandle,
        ] {
            assert_eq!(
                BundledRuntimeLaunchSpec::new(
                    PathBuf::from("/opt/gocode/gocoded"),
                    BundledRuntimeLaunchMode::Direct,
                    Some(transport),
                ),
                Err(BundledRuntimeLaunchError::SecretTransportUnsupported)
            );
        }
    }

    #[test]
    fn supervisor_spawns_then_waits_for_authenticated_readiness() {
        let start = Instant::now();
        let clock = FakeClock::new(start);
        let (launcher, spawn_count) = FakeLauncher::new([Ok(FakeProcess::running())]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());

        supervisor.start().expect("spawn succeeds");
        assert_eq!(spawn_count.get(), 1);
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::Handshaking
        );

        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("matching authenticated handshake");
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Ready);
    }

    #[test]
    fn supervisor_fails_closed_when_spawn_fails() {
        let clock = FakeClock::new(Instant::now());
        let (launcher, spawn_count) = FakeLauncher::new([Err(()), Ok(FakeProcess::running())]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());

        assert_eq!(
            supervisor.start(),
            Err(BundledRuntimeSupervisorError::SpawnFailed)
        );
        assert_eq!(spawn_count.get(), 1);
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::FailedStart
        );

        prepare_next_profile_binding(&mut supervisor, &runtime_session());
        supervisor
            .start()
            .expect("explicit retry after failed start");
        assert_eq!(spawn_count.get(), 2);
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::Handshaking
        );
    }

    #[test]
    fn supervisor_fails_closed_without_a_secure_replay_profile_binding() {
        let clock = FakeClock::new(Instant::now());
        let (launcher, spawn_count) = FakeLauncher::new([Ok(FakeProcess::running())]);
        let unbound_spec = BundledRuntimeLaunchSpec::new(
            PathBuf::from("/opt/gocode/gocoded"),
            BundledRuntimeLaunchMode::Direct,
            None,
        )
        .expect("valid unbound launch spec");
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, unbound_spec);

        assert_eq!(
            supervisor.start(),
            Err(BundledRuntimeSupervisorError::ProfileBindingUnavailable)
        );
        assert_eq!(spawn_count.get(), 0);
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::FailedStart
        );
    }

    #[test]
    fn supervisor_rejects_repeated_start_without_replacing_the_owned_launch() {
        let clock = FakeClock::new(Instant::now());
        let (launcher, spawn_count) =
            FakeLauncher::new([Ok(FakeProcess::running()), Ok(FakeProcess::running())]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());

        supervisor.start().expect("initial spawn");
        let original_binding = supervisor
            .profile_binding
            .clone()
            .expect("owned profile binding");
        assert_eq!(
            supervisor.start(),
            Err(BundledRuntimeSupervisorError::AlreadyRunning)
        );
        assert_eq!(spawn_count.get(), 1);
        assert!(
            supervisor
                .profile_binding
                .as_ref()
                .is_some_and(|binding| binding == &original_binding)
        );
    }

    #[test]
    fn supervisor_rejects_a_stale_authenticated_handshake() {
        let clock = FakeClock::new(Instant::now());
        let (launcher, _) =
            FakeLauncher::new([Ok(FakeProcess::exited()), Ok(FakeProcess::running())]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock.clone(), launch_spec());
        supervisor.start().expect("first spawn");
        let mut stale_session = runtime_session();
        stale_session.daemon_instance_id = "0199d55d-1a23-7000-8000-000000000003".to_owned();
        stale_session.session_id = "2".repeat(32);
        let stale_handshake = BundledRuntimeAuthenticatedHandshake::for_test(stale_session);
        supervisor.monitor().expect("observe first exit");
        let mut restarted_session = runtime_session();
        restarted_session.daemon_instance_id = "0199d55d-1a23-7000-8000-000000000004".to_owned();
        prepare_next_profile_binding(&mut supervisor, &restarted_session);
        clock.advance(Duration::from_secs(1));
        supervisor.monitor().expect("restart owned process");

        assert_eq!(
            supervisor.record_authenticated_ready(&stale_handshake),
            Err(BundledRuntimeSupervisorError::HandshakeMismatch)
        );
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::Handshaking
        );
    }

    #[test]
    fn supervisor_gracefully_stops_only_the_current_owned_launch() {
        let clock = FakeClock::new(Instant::now());
        let (process, graceful_stop_requests, termination_requests) =
            FakeProcess::with_stop_tracking([BundledRuntimeProcessStatus::Exited]);
        let (launcher, _) = FakeLauncher::new([Ok(process)]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());
        supervisor.start().expect("spawn owned process");
        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("prove current owned launch");

        assert_eq!(
            supervisor.stop(
                &authenticated_handshake(),
                BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT
            ),
            Ok(BundledRuntimeStopDisposition::Graceful)
        );
        assert_eq!(graceful_stop_requests.get(), 1);
        assert_eq!(termination_requests.get(), 0);
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopped);
    }

    #[test]
    fn supervisor_forces_only_the_owned_process_after_graceful_timeout() {
        let clock = FakeClock::new(Instant::now());
        let (process, graceful_stop_requests, termination_requests) =
            FakeProcess::with_stop_tracking([
                BundledRuntimeProcessStatus::Running,
                BundledRuntimeProcessStatus::Exited,
            ]);
        let (launcher, _) = FakeLauncher::new([Ok(process)]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());
        supervisor.start().expect("spawn owned process");
        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("prove current owned launch");

        assert_eq!(
            supervisor.stop(
                &authenticated_handshake(),
                BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT
            ),
            Ok(BundledRuntimeStopDisposition::Forced)
        );
        assert_eq!(graceful_stop_requests.get(), 1);
        assert_eq!(termination_requests.get(), 1);
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopped);
    }

    #[test]
    fn supervisor_retains_owned_process_when_forced_stop_is_unconfirmed() {
        let clock = FakeClock::new(Instant::now());
        let (process, graceful_stop_requests, termination_requests) =
            FakeProcess::with_stop_tracking([
                BundledRuntimeProcessStatus::Running,
                BundledRuntimeProcessStatus::Running,
                BundledRuntimeProcessStatus::Exited,
            ]);
        let (launcher, _) = FakeLauncher::new([Ok(process)]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());
        supervisor.start().expect("spawn owned process");
        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("prove current owned launch");

        assert_eq!(
            supervisor.stop(
                &authenticated_handshake(),
                BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT
            ),
            Err(BundledRuntimeSupervisorError::ForcedStopUnconfirmed)
        );
        assert_eq!(graceful_stop_requests.get(), 1);
        assert_eq!(termination_requests.get(), 1);
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopping);

        supervisor.monitor().expect("retain supervision until exit");
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Stopped);
    }

    #[test]
    fn supervisor_restores_retryable_ownership_after_graceful_stop_io_failures() {
        for process in [
            FakeProcess::with_stop_failures(true, false),
            FakeProcess::with_stop_failures(false, true),
        ] {
            let clock = FakeClock::new(Instant::now());
            let (launcher, _) = FakeLauncher::new([Ok(process)]);
            let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());
            supervisor.start().expect("spawn owned process");
            supervisor
                .record_authenticated_ready(&authenticated_handshake())
                .expect("prove current owned launch");

            assert!(matches!(
                supervisor.stop(
                    &authenticated_handshake(),
                    BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT
                ),
                Err(BundledRuntimeSupervisorError::GracefulStopUnavailable
                    | BundledRuntimeSupervisorError::ProcessStatusUnavailable)
            ));
            assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Ready);
        }
    }

    #[test]
    fn supervisor_rejects_stale_ownership_without_stopping_the_current_launch() {
        let clock = FakeClock::new(Instant::now());
        let (process, graceful_stop_requests, termination_requests) =
            FakeProcess::with_stop_tracking([BundledRuntimeProcessStatus::Running]);
        let (launcher, _) = FakeLauncher::new([Ok(process)]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock, launch_spec());
        supervisor.start().expect("spawn owned process");
        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("prove current owned launch");
        let mut stale_session = runtime_session();
        stale_session.session_id = "2".repeat(32);

        assert_eq!(
            supervisor.stop(
                &BundledRuntimeAuthenticatedHandshake::for_test(stale_session),
                BUNDLED_RUNTIME_GRACEFUL_STOP_TIMEOUT,
            ),
            Err(BundledRuntimeSupervisorError::ShutdownOwnershipMismatch)
        );
        assert_eq!(graceful_stop_requests.get(), 0);
        assert_eq!(termination_requests.get(), 0);
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Ready);
    }

    #[test]
    fn supervisor_restarts_after_an_unexpected_exit_and_backoff() {
        let start = Instant::now();
        let clock = FakeClock::new(start);
        let (launcher, spawn_count) =
            FakeLauncher::new([Ok(FakeProcess::exited()), Ok(FakeProcess::running())]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock.clone(), launch_spec());

        supervisor.start().expect("initial spawn");
        supervisor.monitor().expect("observe unexpected exit");
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Backoff);
        assert_eq!(spawn_count.get(), 1);

        prepare_next_profile_binding(&mut supervisor, &runtime_session());
        clock.advance(Duration::from_secs(1));
        supervisor.monitor().expect("restart after backoff");
        assert_eq!(spawn_count.get(), 2);
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::Handshaking
        );
    }

    #[test]
    fn supervisor_marks_a_failed_delayed_restart_as_failed_start() {
        let start = Instant::now();
        let clock = FakeClock::new(start);
        let (launcher, spawn_count) = FakeLauncher::new([Ok(FakeProcess::exited()), Err(())]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock.clone(), launch_spec());

        supervisor.start().expect("initial spawn");
        supervisor.monitor().expect("observe unexpected exit");
        prepare_next_profile_binding(&mut supervisor, &runtime_session());
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            supervisor.monitor(),
            Err(BundledRuntimeSupervisorError::SpawnFailed)
        );
        assert_eq!(spawn_count.get(), 2);
        assert_eq!(
            supervisor.state(),
            BundledRuntimeLifecycleState::FailedStart
        );
    }

    #[test]
    fn supervisor_exhausts_restart_budget_and_stable_readiness_resets_it() {
        let start = Instant::now();
        let clock = FakeClock::new(start);
        let (launcher, spawn_count) = FakeLauncher::new([
            Ok(FakeProcess::exited()),
            Ok(FakeProcess::exited()),
            Ok(FakeProcess::exited()),
            Ok(FakeProcess::exited()),
            Ok(FakeProcess::exited()),
            Ok(FakeProcess::exited()),
        ]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock.clone(), launch_spec());

        supervisor.start().expect("initial spawn");
        for delay in [1, 2, 5, 10, 30] {
            supervisor.monitor().expect("observe unexpected exit");
            assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Backoff);
            prepare_next_profile_binding(&mut supervisor, &runtime_session());
            clock.advance(Duration::from_secs(delay));
            supervisor.monitor().expect("restart after backoff");
        }
        supervisor.monitor().expect("sixth unexpected exit");
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Exhausted);
        assert_eq!(spawn_count.get(), 6);

        let (launcher, spawn_count) = FakeLauncher::new([Ok(FakeProcess::with_statuses([
            BundledRuntimeProcessStatus::Running,
            BundledRuntimeProcessStatus::Exited,
        ]))]);
        let mut supervisor = BundledRuntimeSupervisor::new(launcher, clock.clone(), launch_spec());
        supervisor.start().expect("fresh supervisor spawn");
        supervisor
            .record_authenticated_ready(&authenticated_handshake())
            .expect("matching authenticated handshake");
        clock.advance(UNEXPECTED_EXIT_WINDOW);
        supervisor.monitor().expect("reset stable readiness budget");
        supervisor.monitor().expect("observe post-reset exit");
        assert_eq!(supervisor.state(), BundledRuntimeLifecycleState::Backoff);
        assert_eq!(spawn_count.get(), 1);
    }

    #[test]
    fn bundled_runtime_backoff_is_bounded_and_stable_authenticated_readiness_resets_the_budget() {
        let start = Instant::now();
        let mut backoff = BundledRuntimeBackoff::new();

        for (index, seconds) in [1, 2, 5, 10, 30].into_iter().enumerate() {
            assert_eq!(
                backoff.record_unexpected_exit(start + Duration::from_secs(index as u64)),
                BundledRuntimeRestartDisposition::RestartAfter(Duration::from_secs(seconds))
            );
        }
        assert_eq!(
            backoff.record_unexpected_exit(start + Duration::from_secs(5)),
            BundledRuntimeRestartDisposition::Exhausted
        );

        backoff.record_authenticated_ready(start + Duration::from_secs(6));
        assert!(!backoff.reset_after_stable_readiness(start + Duration::from_secs(599)));
        assert!(
            backoff.reset_after_stable_readiness(
                start + Duration::from_secs(6) + UNEXPECTED_EXIT_WINDOW
            )
        );
        assert_eq!(
            backoff.record_unexpected_exit(start + Duration::from_secs(6) + UNEXPECTED_EXIT_WINDOW),
            BundledRuntimeRestartDisposition::RestartAfter(Duration::from_secs(1))
        );
    }

    #[test]
    fn bundled_runtime_backoff_requires_continuous_authenticated_readiness() {
        let start = Instant::now();
        let mut backoff = BundledRuntimeBackoff::new();

        backoff.record_authenticated_ready(start);
        backoff.record_disconnected();
        backoff.record_authenticated_ready(start + Duration::from_secs(1));

        assert!(!backoff.reset_after_stable_readiness(start + UNEXPECTED_EXIT_WINDOW));
        assert!(
            backoff.reset_after_stable_readiness(
                start + Duration::from_secs(1) + UNEXPECTED_EXIT_WINDOW
            )
        );

        backoff.record_authenticated_ready(start + UNEXPECTED_EXIT_WINDOW);
        let _ =
            backoff.record_unexpected_exit(start + UNEXPECTED_EXIT_WINDOW + Duration::from_secs(1));
        assert!(
            !backoff.reset_after_stable_readiness(
                start + UNEXPECTED_EXIT_WINDOW + UNEXPECTED_EXIT_WINDOW
            )
        );
    }

    #[test]
    fn bundled_runtime_backoff_enforces_the_rolling_ten_minute_exit_window() {
        let start = Instant::now();
        let mut backoff = BundledRuntimeBackoff::new();

        for seconds in [1, 2, 5, 10, 30] {
            assert_eq!(
                backoff.record_unexpected_exit(start),
                BundledRuntimeRestartDisposition::RestartAfter(Duration::from_secs(seconds))
            );
        }
        assert_eq!(
            backoff.record_unexpected_exit(start + Duration::from_secs(599)),
            BundledRuntimeRestartDisposition::Exhausted
        );
        assert_eq!(
            backoff.record_unexpected_exit(start + UNEXPECTED_EXIT_WINDOW),
            BundledRuntimeRestartDisposition::RestartAfter(Duration::from_secs(1))
        );
    }

    #[test]
    fn profile_lock_rejects_a_concurrent_owner_and_recovers_after_drop() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("profile.lock");

        let first = ProfileLock::acquire(&path).expect("acquire first owner");
        let error = ProfileLock::acquire(&path).expect_err("reject second owner");
        assert_eq!(error.to_string(), "profile is already owned");

        drop(first);
        ProfileLock::acquire(&path).expect("lock released with owner");
    }

    #[test]
    fn restored_window_is_clamped_to_the_current_display_work_area() {
        let work_area = DisplayWorkArea {
            x: 0,
            y: 24,
            width: 1_920,
            height: 1_056,
        };
        let stored = WindowGeometry {
            x: 2_100,
            y: -400,
            width: 2_400,
            height: 1_400,
        };

        assert_eq!(
            restore_window_geometry(stored, work_area),
            WindowGeometry {
                x: 0,
                y: 24,
                width: 1_920,
                height: 1_056,
            }
        );
    }

    #[test]
    fn invalid_or_too_small_geometry_uses_the_documented_safe_default() {
        let work_area = DisplayWorkArea {
            x: 0,
            y: 0,
            width: 1_600,
            height: 900,
        };
        let stored = WindowGeometry {
            x: 50,
            y: 50,
            width: 100,
            height: 100,
        };

        assert_eq!(
            restore_window_geometry(stored, work_area),
            WindowGeometry {
                x: 80,
                y: 0,
                width: 1_440,
                height: 900,
            }
        );
    }
}
