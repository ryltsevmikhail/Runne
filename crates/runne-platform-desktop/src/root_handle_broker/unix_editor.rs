use std::fs;
use std::process::Command;

pub(super) fn launch_system_default_editor(
    root: &NativeDirectoryHandle,
    relative_path: &Path,
) -> Result<(), RootHandleBrokerError> {
    open_file_below(root, relative_path)?;
    let root_path = root_path(root)?;
    let target = root_path.join(relative_path);
    let opener = default_opener()?;
    Command::new(opener)
        .arg(target)
        .env_clear()
        .envs(allowlisted_environment())
        .spawn()
        .map(|_| ())
        .map_err(|_| RootHandleBrokerError::Unavailable)
}

fn root_path(root: &NativeDirectoryHandle) -> Result<std::path::PathBuf, RootHandleBrokerError> {
    #[cfg(target_os = "linux")]
    let descriptor = format!("/proc/self/fd/{}", root.as_raw_fd());
    #[cfg(target_os = "macos")]
    let descriptor = format!("/dev/fd/{}", root.as_raw_fd());
    fs::read_link(descriptor).map_err(|_| RootHandleBrokerError::Unavailable)
}

#[cfg(target_os = "linux")]
fn default_opener() -> Result<&'static str, RootHandleBrokerError> {
    ["/usr/bin/xdg-open", "/bin/xdg-open"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .ok_or(RootHandleBrokerError::Unavailable)
}

#[cfg(target_os = "macos")]
const fn default_opener() -> Result<&'static str, RootHandleBrokerError> {
    Ok("/usr/bin/open")
}

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
