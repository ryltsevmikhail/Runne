//! Desktop implementations of native capability ports.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;

use thiserror::Error;

const MINIMUM_WINDOW_WIDTH: i32 = 960;
const MINIMUM_WINDOW_HEIGHT: i32 = 600;
const DEFAULT_WINDOW_WIDTH: i32 = 1_440;
const DEFAULT_WINDOW_HEIGHT: i32 = 900;

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
    use super::{DisplayWorkArea, ProfileLock, WindowGeometry, restore_window_geometry};

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
