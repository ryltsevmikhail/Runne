#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(feature = "test-support")]
use std::sync::atomic::{AtomicU32, Ordering};

pub(super) fn launch_system_default_editor(
    root: &NativeDirectoryHandle,
    relative_path: &Path,
) -> Result<(), RootHandleBrokerError> {
    open_file_below(root, relative_path)?;
    #[cfg(target_os = "macos")]
    {
        // deliberate temporary macOS backend limitation: the opener target is re-resolved from a PATH the validation cannot pin to the checked object (/dev/fd readlink is EINVAL on macOS 27); fail closed after the shared checks; Linux/Windows keep their launch path
        Err(RootHandleBrokerError::Unavailable)
    }
    #[cfg(target_os = "linux")]
    {
        let root_path = root_path(root)?;
        let target = root_path.join(relative_path);
        let opener = default_opener()?;
        #[cfg(feature = "test-support")]
        LAUNCHER_SPAWN_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        Command::new(opener)
            .arg(target)
            .env_clear()
            .envs(allowlisted_environment())
            .spawn()
            .map(|_| ())
            .map_err(|_| RootHandleBrokerError::Unavailable)
    }
}

#[cfg(target_os = "linux")]
fn root_path(root: &NativeDirectoryHandle) -> Result<std::path::PathBuf, RootHandleBrokerError> {
    let descriptor = format!("/proc/self/fd/{}", root.as_raw_fd());
    fs::read_link(descriptor).map_err(|_| RootHandleBrokerError::Unavailable)
}

#[cfg(target_os = "linux")]
fn default_opener() -> Result<&'static str, RootHandleBrokerError> {
    ["/usr/bin/xdg-open", "/bin/xdg-open"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .ok_or(RootHandleBrokerError::Unavailable)
}

#[cfg(target_os = "linux")]
fn allowlisted_environment() -> Vec<(String, String)> {
    [
        "DBUS_SESSION_BUS_ADDRESS",
        "DISPLAY",
        "HOME",
        "PATH",
        "USER",
        "WAYLAND_DISPLAY",
        "XDG_CURRENT_DESKTOP",
        "XDG_RUNTIME_DIR",
    ]
    .into_iter()
    .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)))
    .collect()
}

#[cfg(feature = "test-support")]
static LAUNCHER_SPAWN_ATTEMPTS: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "test-support")]
#[doc(hidden)]
#[must_use]
pub(super) fn launcher_spawn_attempt_count() -> u32 {
    LAUNCHER_SPAWN_ATTEMPTS.load(Ordering::Relaxed)
}
