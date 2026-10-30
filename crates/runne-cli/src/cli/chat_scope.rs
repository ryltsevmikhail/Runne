//! Native chat owner scope; this is scheduling setup, never tool admission.
use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::IsTerminal as _,
    os::unix::{
        fs::{FileTypeExt as _, MetadataExt as _},
        process::CommandExt as _,
    },
    path::{Component, Path, PathBuf},
    process::Command,
};

const MARKER: &str = "RUNNE_CHAT_DELEGATED_SCOPE_V1";

pub fn ensure(arguments: &[OsString]) -> Result<(), String> {
    if !should_route(arguments)
        || !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
    {
        return Ok(());
    }
    if !needs_scope(delegated(), std::env::var_os(MARKER).is_some())? {
        return Ok(());
    }
    let uid = rustix::process::getuid().as_raw();
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    let bus = runtime.join("bus");
    let root =
        fs::symlink_metadata(&runtime).map_err(|_| "Systemd user runtime directory unavailable")?;
    let socket = fs::symlink_metadata(&bus).map_err(|_| "Systemd user bus unavailable")?;
    if !root.is_dir()
        || root.uid() != uid
        || root.mode() & 0o022 != 0
        || !socket.file_type().is_socket()
        || socket.uid() != uid
    {
        return Err("Systemd user bus ownership is invalid".into());
    }
    let executable =
        std::env::current_exe().map_err(|_| "Cannot resolve the native CLI executable")?;
    if !executable.is_absolute() {
        return Err("Native CLI executable path is not absolute".into());
    }
    // Scope mode inherits terminal descriptors and the caller's environment.
    // systemd-run needs the real runtime directory; --setenv restores the
    // profile directory in the child after the scope has been created.
    let error = Command::new("/usr/bin/systemd-run")
        .args(scope_arguments(
            &executable,
            arguments,
            std::env::var_os("XDG_RUNTIME_DIR").as_deref(),
        ))
        .env("XDG_RUNTIME_DIR", &runtime)
        .env(MARKER, "1")
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path={}", bus.display()),
        )
        .exec();
    Err(format!("Cannot start a delegated chat scope: {error}"))
}

const fn needs_scope(delegated: bool, attempted: bool) -> Result<bool, &'static str> {
    if delegated {
        Ok(false)
    } else if attempted {
        Err(
            "Chat could not obtain a writable delegated user cgroup; check your systemd user manager. Tool admission remains closed.",
        )
    } else {
        Ok(true)
    }
}

fn should_route(arguments: &[OsString]) -> bool {
    crate::tui_backend::selected(arguments)
        && !arguments.iter().any(|arg| arg == "--help" || arg == "-h")
}

fn scope_arguments(
    executable: &Path,
    arguments: &[OsString],
    runtime: Option<&std::ffi::OsStr>,
) -> Vec<OsString> {
    let mut result: Vec<OsString> = [
        "--user",
        "--scope",
        "--quiet",
        "--expand-environment=no",
        "-p",
        "Delegate=yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    if let Some(runtime) = runtime {
        let mut option = OsString::from("--setenv=XDG_RUNTIME_DIR=");
        option.push(runtime);
        result.push(option);
    }
    result.push(OsString::from("--"));
    result.push(executable.as_os_str().to_owned());
    result.extend_from_slice(arguments);
    result
}

fn unified_path(text: &str) -> Option<PathBuf> {
    let mut paths = text.lines().filter_map(|line| line.strip_prefix("0::"));
    let path = Path::new(paths.next()?);
    if paths.next().is_some()
        || !path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return None;
    }
    Some(Path::new("/sys/fs/cgroup").join(path.strip_prefix("/").ok()?))
}

fn delegated() -> bool {
    let Ok(membership) = fs::read_to_string("/proc/self/cgroup") else {
        return false;
    };
    let Some(path) = unified_path(&membership) else {
        return false;
    };
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return false;
    };
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::getuid().as_raw()
        || metadata.mode() & 0o200 == 0
    {
        return false;
    }
    ["cgroup.procs", "cgroup.subtree_control"]
        .iter()
        .all(|name| OpenOptions::new().write(true).open(path.join(name)).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }
    #[test]
    fn only_chat_routes_and_help_never_reexecutes() {
        for value in [
            vec![],
            args(&["chat"]),
            args(&["--profile", "/a b", "chat"]),
        ] {
            assert!(should_route(&value));
        }
        for value in [
            args(&["chat", "--help"]),
            args(&["--help"]),
            args(&["status"]),
            args(&["provider", "credential"]),
            args(&["exec"]),
            args(&["--version"]),
        ] {
            assert!(!should_route(&value));
        }
    }
    #[test]
    fn reexec_preserves_argument_boundaries_and_has_no_shell() {
        let original = args(&["chat", "--project", "/a b/$(literal)"]);
        let command = scope_arguments(Path::new("/release/runne"), &original, None);
        assert_eq!(
            &command[..8],
            &args(&[
                "--user",
                "--scope",
                "--quiet",
                "--expand-environment=no",
                "-p",
                "Delegate=yes",
                "--",
                "/release/runne"
            ])
        );
        assert_eq!(&command[8..], original);
    }
    #[test]
    fn scope_manager_and_child_runtime_directories_are_separate() {
        let original = args(&["chat"]);
        let runtime = std::ffi::OsStr::new("/tmp/profile with spaces");
        let command = scope_arguments(Path::new("/release/runne"), &original, Some(runtime));
        assert_eq!(
            command[6],
            "--setenv=XDG_RUNTIME_DIR=/tmp/profile with spaces"
        );
        assert_eq!(command[7], "--");
        assert_eq!(command[8], "/release/runne");
        assert_eq!(command[9], "chat");
    }
    #[test]
    fn recursion_marker_never_substitutes_for_kernel_delegation() {
        assert_eq!(needs_scope(false, false), Ok(true));
        assert!(needs_scope(false, true).is_err());
        assert_eq!(needs_scope(true, false), Ok(false));
        assert_eq!(needs_scope(true, true), Ok(false));
    }
    #[test]
    fn kernel_membership_is_exact_unified_and_cannot_traverse() {
        assert_eq!(
            unified_path("0::/user.slice/run.scope\n"),
            Some(PathBuf::from("/sys/fs/cgroup/user.slice/run.scope"))
        );
        for invalid in ["0::/../outside", "0::relative", "0::/a\n0::/b", "1:cpu:/x"] {
            assert!(unified_path(invalid).is_none());
        }
    }
}
