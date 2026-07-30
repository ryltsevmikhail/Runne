//! Desktop implementations of native capability ports.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundledRuntimeLaunchSpec {
    executable: PathBuf,
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
        Ok(Self { executable })
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

/// The next action after an unexpected bundled-runtime exit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BundledRuntimeRestartDisposition {
    RestartAfter(Duration),
    Exhausted,
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
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use super::{
        BundledRuntimeBackoff, BundledRuntimeLaunchError, BundledRuntimeLaunchMode,
        BundledRuntimeLaunchSpec, BundledRuntimeRestartDisposition, BundledRuntimeSecretTransport,
        DisplayWorkArea, ProfileLock, UNEXPECTED_EXIT_WINDOW, WindowGeometry,
        restore_window_geometry,
    };

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
