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
