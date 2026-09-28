#[cfg(feature = "test-support")]
use std::sync::atomic::{AtomicU32, Ordering};

pub(super) fn launch_system_default_editor(
    root: &NativeDirectoryHandle,
    relative_path: &Path,
) -> Result<(), RootHandleBrokerError> {
    open_file_below(root, relative_path)?;
    #[cfg(target_os = "macos")]
    {
        // The macOS opener target cannot be pinned to the checked object; fail
        // closed after shared validation until a handle-bound opener exists.
        Err(RootHandleBrokerError::Unavailable)
    }
    #[cfg(target_os = "linux")]
    {
        // xdg-open resolves a path string after this checked descriptor closes.
        // Until the opener accepts a handle-bound target, keep the Linux editor
        // unavailable rather than handing it a replaceable workspace path.
        Err(RootHandleBrokerError::Unavailable)
    }
}

#[cfg(feature = "test-support")]
static LAUNCHER_SPAWN_ATTEMPTS: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "test-support")]
#[doc(hidden)]
#[must_use]
pub(super) fn launcher_spawn_attempt_count() -> u32 {
    LAUNCHER_SPAWN_ATTEMPTS.load(Ordering::Relaxed)
}
