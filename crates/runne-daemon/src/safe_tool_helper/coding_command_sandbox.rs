//! macOS command execution through the signed Seatbelt helper.
//!
//! The runtime renders one profile, passes it over an inherited descriptor and
//! lets the helper apply it, enter the pinned working directory and replace
//! itself with the resolved program. The runtime never interprets a shell
//! string and never accepts profile text from a caller.
//!
//! Helper failures are reported on a second inherited descriptor that the
//! helper arms close-on-exec. Only the helper ever holds that descriptor, so a
//! program that writes a helper-looking diagnostic to stderr and picks one of
//! the helper's exit codes cannot be mistaken for a helper failure.

use super::coding_arguments::CodingArguments;
use super::*;
use runne_platform::containment::macos::MacOsSeatbeltProfileV1;
use runne_sandbox_protocol::{self as protocol, Report};
use security_framework::os::macos::code_signing::{Flags, SecRequirement, SecStaticCode};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;

/// Bundled helper name.
const HELPER_NAME: &str = "runne-sandbox-helper";
/// Team that must have signed the helper before the runtime executes it.
const SIGNING_TEAM: &str = "758F9Z45SR";
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
    let (profile_read, profile_write) = profile_pipe()?;
    let (status_read, status_write) = status_pipe()?;

    let mut command = Command::new(&helper);
    command
        .arg(protocol::STATUS_FD_FLAG)
        .arg(status_write.to_string())
        .arg("--profile-fd")
        .arg(profile_read.to_string())
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
            // No helper inherited either descriptor pair, so every end still
            // belongs to this process.
            close_descriptors([profile_read, profile_write, status_read, status_write]);
            return Err(spawn_error(&error));
        }
    };
    // The helper owns the inherited ends from here. Keeping the profile read
    // end open would leave the helper waiting for end-of-profile, and keeping
    // the status write end open would hide end-of-exec from this process.
    close_descriptors([profile_read, status_write]);
    // SAFETY: the runtime owns the status read end and closes it exactly once
    // when this file value is dropped.
    let mut status = unsafe { File::from_raw_fd(status_read) };
    if write_profile(profile_write, &profile.render()).is_err() {
        halt(&mut child);
        return Err(match protocol::classify(&read_status(&mut status)) {
            Report::Failed(code) => helper_error(code),
            Report::Started | Report::Unconfirmed => "command_profile_write",
        });
    }
    let collected = coding_process::collect(&mut child, args.timeout_ms)?;
    // Only the helper can have written here: the descriptor never reaches the
    // program, so this report decides between a helper failure and a receipt
    // for a program that really ran.
    match protocol::classify(&read_status(&mut status)) {
        Report::Started => coding_process::receipt(collected),
        Report::Failed(code) => Err(helper_error(code)),
        Report::Unconfirmed => Err(protocol::PROTOCOL_ERROR),
    }
}

/// Tool error for one helper status byte; unknown bytes never become receipts.
fn helper_error(status: u8) -> &'static str {
    protocol::error_for(status).unwrap_or(protocol::PROTOCOL_ERROR)
}

/// Stops the whole helper process group and reaps it.
fn halt(child: &mut Child) {
    // SAFETY: the child leads the process group this runtime created for it,
    // so a negated pid addresses that group.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.wait();
}

/// Reads every status byte recorded before the descriptor reached end-of-file.
///
/// The read end is non-blocking: a descriptor that outlived its writer yields
/// whatever was recorded instead of stalling the runtime.
fn read_status(status: &mut File) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8];
    loop {
        match status.read(&mut buffer) {
            Ok(0) | Err(_) => return bytes,
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
        }
    }
}

fn spawn_error(error: &std::io::Error) -> &'static str {
    match error.raw_os_error() {
        Some(libc::EACCES) => "command_spawn_access",
        Some(libc::ENOENT) => "command_spawn_missing",
        Some(libc::EPERM) => "command_spawn_policy",
        _ => "command_spawn_other",
    }
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
    let (read, write) = create_pipe("command_profile_pipe")?;
    let configured = set_close_on_exec(read, false).and_then(|()| set_close_on_exec(write, true));
    if let Err(error) = configured {
        close_descriptors([read, write]);
        return Err(error);
    }
    Ok((read, write))
}

/// Creates the status pipe: the helper inherits the write end and arms it
/// close-on-exec itself, while the runtime keeps a non-blocking read end.
fn status_pipe() -> Result<(RawFd, RawFd), &'static str> {
    let (read, write) = create_pipe("command_status_pipe")?;
    let configured = set_close_on_exec(read, true)
        .and_then(|()| set_close_on_exec(write, false))
        .and_then(|()| set_nonblocking(read));
    if configured.is_err() {
        close_descriptors([read, write]);
        return Err("command_status_pipe");
    }
    Ok((read, write))
}

fn create_pipe(error: &'static str) -> Result<(RawFd, RawFd), &'static str> {
    let mut descriptors = [0; 2];
    // SAFETY: the array holds exactly the two descriptors the kernel fills.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(error);
    }
    Ok((descriptors[0], descriptors[1]))
}

fn close_descriptors(descriptors: impl IntoIterator<Item = RawFd>) {
    for descriptor in descriptors {
        // SAFETY: each descriptor still belongs to this process here and is
        // closed exactly once.
        unsafe {
            libc::close(descriptor);
        }
    }
}

fn write_profile(fd: RawFd, profile: &str) -> Result<(), &'static str> {
    // SAFETY: the runtime owns the write end and closes it exactly once when
    // this file value is dropped.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(profile.as_bytes())
        .map_err(|_| "command_profile_write")
}

fn set_nonblocking(fd: RawFd) -> Result<(), &'static str> {
    // SAFETY: F_GETFL and F_SETFL only inspect and update this descriptor's
    // flags.
    let current = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if current < 0 {
        return Err("command_status_pipe");
    }
    // SAFETY: same as above; the flag word is only modified bitwise.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, current | libc::O_NONBLOCK) } < 0 {
        return Err("command_status_pipe");
    }
    Ok(())
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

#[cfg(test)]
#[path = "coding_command_sandbox_tests.rs"]
mod tests;
