//! macOS command execution through the signed Seatbelt helper.
//!
//! The runtime renders one profile, passes it over an inherited descriptor and
//! lets the helper apply it, enter the pinned working directory and replace
//! itself with the resolved program. The runtime never interprets a shell
//! string and never accepts profile text from a caller.

use super::coding_arguments::CodingArguments;
use super::*;
use runne_platform::containment::macos::MacOsSeatbeltProfileV1;
use security_framework::os::macos::code_signing::{Flags, SecRequirement, SecStaticCode};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;

/// Bundled helper name.
const HELPER_NAME: &str = "runne-sandbox-helper";
/// Team that must have signed the helper before the runtime executes it.
const SIGNING_TEAM: &str = "758F9Z45SR";
/// Prefix the helper writes for each of its own failures.
const HELPER_DIAGNOSTIC: &str = "runne-sandbox-helper:";
/// Directories an unqualified program name is resolved against.
const SEARCH_PATH: &[&str] = &["/usr/bin", "/bin"];

pub(super) fn run(root: &File, args: &CodingArguments) -> Result<Vec<u8>, &'static str> {
    let workspace = coding_fs::pinned_path(root)?;
    let profile = MacOsSeatbeltProfileV1::new(&workspace).map_err(|_| "command_profile_denied")?;
    let helper = helper_binary()?;
    verify_helper(&helper)?;
    let program = absolute_program(&args.argv[0])?;
    let cwd = coding_fs::open(root, &args.path, O_PATH | libc::O_DIRECTORY)?;
    let cwd_fd = cwd.as_raw_fd();
    set_close_on_exec(cwd_fd, false)?;
    let (read_fd, write_fd) = profile_pipe()?;

    let mut command = Command::new(&helper);
    command
        .arg("--profile-fd")
        .arg(read_fd.to_string())
        .arg("--cwd-fd")
        .arg(cwd_fd.to_string())
        .arg("--")
        .arg(&program)
        .args(&args.argv[1..])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            // No helper inherited the read end, and the write end was never
            // handed to `write_profile`, so both descriptors still belong here.
            unsafe {
                libc::close(read_fd);
                libc::close(write_fd);
            }
            return Err(match error.raw_os_error() {
                Some(libc::EACCES) => "command_spawn_access",
                Some(libc::ENOENT) => "command_spawn_missing",
                Some(libc::EPERM) => "command_spawn_policy",
                _ => "command_spawn_other",
            });
        }
    };
    // The helper owns the read end from here; keeping it open in the parent
    // would leave the helper waiting for end-of-profile.
    unsafe {
        libc::close(read_fd);
    }
    if write_profile(write_fd, &profile.render()).is_err() {
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.wait();
        return Err("command_profile_write");
    }
    let collected = coding_process::collect(&mut child, args.timeout_ms)?;
    if let Some(error) = helper_failure(&collected) {
        return Err(error);
    }
    coding_process::receipt(collected)
}

/// Separates a helper failure from a program that happened to use its exit
/// codes: only an empty stdout plus the helper's own diagnostic prefix counts.
fn helper_failure(collected: &coding_process::Collected) -> Option<&'static str> {
    let code = collected.status.code()?;
    if !collected.stdout.is_empty() || !diagnostic_line(&collected.stderr) {
        return None;
    }
    match code {
        2 => Some("command_helper_usage"),
        3 => Some("command_spawn_policy"),
        4 => Some("command_profile_denied"),
        5 => Some("command_cwd_denied"),
        6 => Some("command_spawn_missing"),
        _ => None,
    }
}

/// Seatbelt writes its own diagnostic before the helper can report, so the
/// helper's message is matched anywhere on its own line rather than at the
/// start of stderr.
fn diagnostic_line(stderr: &[u8]) -> bool {
    stderr
        .split(|byte| *byte == b'\n')
        .any(|line| line.starts_with(HELPER_DIAGNOSTIC.as_bytes()))
}

/// Locates the bundled helper: beside the daemon, or one level up for cargo's
/// `deps` test layout.
fn helper_binary() -> Result<PathBuf, &'static str> {
    let executable = std::env::current_exe().map_err(|_| "command_helper_missing")?;
    let directory = executable.parent().ok_or("command_helper_missing")?;
    [
        directory.join(HELPER_NAME),
        directory.join("..").join(HELPER_NAME),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
    .ok_or("command_helper_missing")
}

/// Requires a Developer ID signature from this product team before the helper
/// is allowed to apply a profile on our behalf.
fn verify_helper(helper: &Path) -> Result<(), &'static str> {
    let location =
        core_foundation::url::CFURL::from_path(helper, false).ok_or("command_helper_untrusted")?;
    let flags = Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS;
    let requirement = SecRequirement::from_str(&format!(
        "anchor apple generic and identifier \"{HELPER_NAME}\" \
         and certificate leaf[subject.OU] = \"{SIGNING_TEAM}\""
    ))
    .map_err(|_| "command_helper_untrusted")?;
    // Creation accepts only path-shaped flags; the validity policy is applied
    // on the check below.
    let code =
        SecStaticCode::from_path(&location, Flags::NONE).map_err(|_| "command_helper_untrusted")?;
    code.check_validity(flags, &requirement)
        .map_err(|_| "command_helper_untrusted")
}

/// Resolves an unqualified program name against a fixed search path, matching
/// what `execvp` would do on Linux. The helper only executes absolute paths.
fn absolute_program(program: &str) -> Result<PathBuf, &'static str> {
    let requested = Path::new(program);
    let located = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        SEARCH_PATH
            .iter()
            .map(|directory| Path::new(directory).join(program))
            .find(|candidate| candidate.is_file())
            .ok_or("command_spawn_missing")?
    };
    let resolved = std::fs::canonicalize(&located).map_err(|_| "command_spawn_missing")?;
    if !resolved.is_file() || resolved.to_str().is_none() {
        return Err("command_spawn_missing");
    }
    Ok(resolved)
}

/// Creates the profile pipe: the read end is inherited by the helper, the
/// write end stays private to the runtime.
fn profile_pipe() -> Result<(RawFd, RawFd), &'static str> {
    let mut descriptors = [0; 2];
    // SAFETY: the array holds exactly the two descriptors the kernel fills.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err("command_profile_pipe");
    }
    let configured = set_close_on_exec(descriptors[0], false)
        .and_then(|()| set_close_on_exec(descriptors[1], true));
    if let Err(error) = configured {
        for descriptor in descriptors {
            unsafe {
                libc::close(descriptor);
            }
        }
        return Err(error);
    }
    Ok((descriptors[0], descriptors[1]))
}

fn write_profile(fd: RawFd, profile: &str) -> Result<(), &'static str> {
    // SAFETY: the runtime owns the write end and closes it exactly once when
    // this file value is dropped.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(profile.as_bytes())
        .map_err(|_| "command_profile_write")
}

fn set_close_on_exec(fd: RawFd, enabled: bool) -> Result<(), &'static str> {
    // SAFETY: F_GETFD and F_SETFD only read and update this descriptor's flags.
    let current = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if current < 0 {
        return Err("command_descriptor");
    }
    let next = if enabled {
        current | libc::FD_CLOEXEC
    } else {
        current & !libc::FD_CLOEXEC
    };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, next) } < 0 {
        return Err("command_descriptor");
    }
    Ok(())
}
