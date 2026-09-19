use std::fs;
use std::process::Command;
// `Path` and `PathBuf` are already in scope: this file is textually included
// by unix.rs, which imports them for the shared platform namespace.

pub(super) fn launch_system_default_editor(
    root: &NativeDirectoryHandle,
    relative_path: &Path,
) -> Result<(), RootHandleBrokerError> {
    #[cfg(target_os = "macos")]
    let validated = open_file_below(root, relative_path)?;
    #[cfg(target_os = "linux")]
    open_file_below(root, relative_path)?;
    let target: PathBuf = root_path(root)?.join(relative_path);
    // macOS hardening: the opener re-resolves the path string on its own, so
    // everything validated above can be swapped out before it opens. Pin the
    // validated file and re-check that the target path still names the same
    // file immediately before spawning (see the macos_tests module for the
    // swap races this closes; the residual verify-to-spawn window and the
    // opener's post-spawn resolution remain a known contract gap).
    #[cfg(target_os = "macos")]
    verify_validated_identity(&validated, &target)?;
    #[cfg(target_os = "macos")]
    let _pinned_until_spawn = validated;
    #[cfg(target_os = "linux")]
    let opener = default_opener()?;
    #[cfg(target_os = "macos")]
    let opener = default_opener();
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
    {
        // macOS 27 no longer resolves /dev/fd/N through readlink (EINVAL for
        // every process), which silently failed every editor launch at base.
        // F_GETPATH is the supported fd-to-path API; like the previous
        // best-effort readlink it reports the vnode's current name.
        let mut path = std::path::PathBuf::new();
        nix::fcntl::fcntl(root, nix::fcntl::FcntlArg::F_GETPATH(&mut path))
            .map_err(|_| RootHandleBrokerError::Unavailable)?;
        return Ok(path);
    }
    #[cfg(target_os = "linux")]
    fs::read_link(descriptor).map_err(|_| RootHandleBrokerError::Unavailable)
}

#[cfg(target_os = "macos")]
fn verify_validated_identity(
    validated: &fs::File,
    target: &Path,
) -> Result<(), RootHandleBrokerError> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};

    let reopened = open(
        target,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| RootHandleBrokerError::Rejected)?;
    let reopened = fstat(&reopened).map_err(|_| RootHandleBrokerError::Unavailable)?;
    let pinned = fstat(validated).map_err(|_| RootHandleBrokerError::Unavailable)?;
    let same_file = reopened.st_dev == pinned.st_dev
        && reopened.st_ino == pinned.st_ino
        && FileType::from_raw_mode(reopened.st_mode).is_file();
    same_file.then_some(()).ok_or(RootHandleBrokerError::Rejected)
}

#[cfg(target_os = "linux")]
fn default_opener() -> Result<&'static str, RootHandleBrokerError> {
    ["/usr/bin/xdg-open", "/bin/xdg-open"]
        .into_iter()
        .find(|path| Path::new(path).is_file())
        .ok_or(RootHandleBrokerError::Unavailable)
}

#[cfg(target_os = "macos")]
const fn default_opener() -> &'static str {
    "/usr/bin/open"
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

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use std::path::Path;

    use super::{NativeDirectoryHandle, open_file_below, root_path, verify_validated_identity};

    fn workspace() -> (tempfile::TempDir, NativeDirectoryHandle) {
        let dir = tempfile::tempdir().expect("temporary workspace");
        std::fs::create_dir_all(dir.path().join("notes")).expect("notes directory");
        std::fs::write(dir.path().join("notes/plan.md"), "CANARY-PLAN").expect("benign file");
        std::fs::write(dir.path().join(".env"), "CANARY-DOTENV").expect("denied file");
        let canonical = std::fs::canonicalize(dir.path()).expect("canonical workspace");
        let root: NativeDirectoryHandle = std::fs::File::open(&canonical).expect("root handle");
        (dir, root)
    }

    /// The editor opener receives only a path string; after a rename swaps the
    /// validated file, that string resolves onto the denied file's content.
    /// This pins the race the identity re-check below defends against.
    #[test]
    fn renamed_target_string_resolves_to_denied_content() {
        let (dir, root) = workspace();
        let validated = open_file_below(&root, Path::new("notes/plan.md")).expect("validated file");
        let target = root_path(&root)
            .expect("root path")
            .join("notes/plan.md");
        verify_validated_identity(&validated, &target).expect("identity before the swap");
        std::fs::rename(dir.path().join(".env"), dir.path().join("notes/plan.md"))
            .expect("attacker rename");
        assert_eq!(
            std::fs::read_to_string(&target).expect("opener-visible content"),
            "CANARY-DOTENV",
            "the spawned opener's path string resolves onto the denied file after the swap"
        );
    }

    #[test]
    fn rename_swap_is_rejected_before_spawn() {
        let (dir, root) = workspace();
        let validated = open_file_below(&root, Path::new("notes/plan.md")).expect("validated file");
        let target = root_path(&root)
            .expect("root path")
            .join("notes/plan.md");
        std::fs::rename(dir.path().join(".env"), dir.path().join("notes/plan.md"))
            .expect("attacker rename");
        assert!(verify_validated_identity(&validated, &target).is_err());
    }

    #[test]
    fn symlink_swap_is_rejected_before_spawn() {
        let (dir, root) = workspace();
        let validated = open_file_below(&root, Path::new("notes/plan.md")).expect("validated file");
        let target = root_path(&root)
            .expect("root path")
            .join("notes/plan.md");
        let link = dir.path().join("staged-link");
        std::os::unix::fs::symlink(dir.path().join(".env"), &link).expect("staged symlink");
        std::fs::rename(&link, dir.path().join("notes/plan.md")).expect("symlink swap");
        assert!(verify_validated_identity(&validated, &target).is_err());
    }

    #[test]
    fn untouched_target_stays_launchable() {
        let (_dir, root) = workspace();
        let validated = open_file_below(&root, Path::new("notes/plan.md")).expect("validated file");
        let target = root_path(&root)
            .expect("root path")
            .join("notes/plan.md");
        verify_validated_identity(&validated, &target).expect("identity holds without a swap");
    }
}
