//! Helper entry point and the in-process Seatbelt self-test.

use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::args::{self, Invocation, Launch};
use crate::exec;
use crate::profile;
use crate::seatbelt;

const EXIT_BAD_USAGE: u8 = 2;
const EXIT_SANDBOX_FAILED: u8 = 3;
const EXIT_PROFILE_INVALID: u8 = 4;
const EXIT_CWD_FAILED: u8 = 5;
const EXIT_EXEC_FAILED: u8 = 6;
const EXIT_DENY_FAILED: u8 = 7;
const EXIT_ALLOW_FAILED: u8 = 8;
const EXIT_SETUP_FAILED: u8 = 9;

/// Parses the invocation and either runs the self-test or launches the target.
pub fn run_or_launch() -> ExitCode {
    let invocation = match args::parse(std::env::args_os().skip(1)) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("runne-sandbox-helper: {message}");
            print_usage();
            return ExitCode::from(EXIT_BAD_USAGE);
        }
    };
    match invocation {
        Invocation::SelfTest => run_self_test(),
        Invocation::Launch(launch) => launch_target(&launch),
    }
}

fn launch_target(launch: &Launch) -> ExitCode {
    let profile = match profile::read(launch.profile_fd) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("runne-sandbox-helper: {message}");
            return ExitCode::from(EXIT_PROFILE_INVALID);
        }
    };
    if let Err(message) = seatbelt::apply(&profile) {
        eprintln!("runne-sandbox-helper: cannot apply the sandbox profile: {message}");
        return ExitCode::from(EXIT_SANDBOX_FAILED);
    }
    if let Some(fd) = launch.cwd_fd {
        // SAFETY: fchdir only reads the descriptor the parent supplied.
        let result = unsafe { libc::fchdir(fd) };
        let error = std::io::Error::last_os_error();
        // The working directory is fixed now; do not leak the descriptor into
        // the program this helper is about to execute.
        // SAFETY: the helper owns the descriptor it was given.
        unsafe { libc::close(fd) };
        if result != 0 {
            eprintln!("runne-sandbox-helper: cannot enter the working directory: {error}");
            return ExitCode::from(EXIT_CWD_FAILED);
        }
    }
    let message = exec::replace(&launch.program, &launch.args);
    eprintln!("runne-sandbox-helper: {message}");
    ExitCode::from(EXIT_EXEC_FAILED)
}

fn run_self_test() -> ExitCode {
    let root = match self_test_root() {
        Ok(value) => value,
        Err(message) => {
            eprintln!("runne-sandbox-helper: self-test setup failed: {message}");
            return ExitCode::from(EXIT_SETUP_FAILED);
        }
    };
    let _cleanup = RemoveDir(root.clone());
    let text = match self_test_profile(&root) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("runne-sandbox-helper: self-test profile failed: {message}");
            return ExitCode::from(EXIT_SETUP_FAILED);
        }
    };
    let Ok(profile) = CString::new(text) else {
        eprintln!("runne-sandbox-helper: self-test profile contains a NUL byte");
        return ExitCode::from(EXIT_SETUP_FAILED);
    };
    if let Err(message) = seatbelt::apply(&profile) {
        eprintln!("runne-sandbox-helper: self-test sandbox failed: {message}");
        return ExitCode::from(EXIT_SANDBOX_FAILED);
    }

    if fs::read("/etc/passwd").is_ok() {
        eprintln!("runne-sandbox-helper: self-test read /etc/passwd despite the profile");
        return ExitCode::from(EXIT_DENY_FAILED);
    }
    let probe = root.join("probe.txt");
    let expected = b"runne-sandbox-helper\n";
    if let Err(error) = fs::write(&probe, expected) {
        eprintln!("runne-sandbox-helper: self-test cannot write the workspace: {error}");
        return ExitCode::from(EXIT_ALLOW_FAILED);
    }
    match fs::read(&probe) {
        Ok(bytes) if bytes == expected => ExitCode::SUCCESS,
        Ok(_) => {
            eprintln!("runne-sandbox-helper: self-test read back the wrong bytes");
            ExitCode::from(EXIT_ALLOW_FAILED)
        }
        Err(error) => {
            eprintln!("runne-sandbox-helper: self-test cannot read the workspace: {error}");
            ExitCode::from(EXIT_ALLOW_FAILED)
        }
    }
}

fn self_test_root() -> Result<PathBuf, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "runne-sandbox-helper-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir(&root).map_err(|error| error.to_string())?;
    fs::canonicalize(&root).map_err(|error| error.to_string())
}

fn self_test_profile(root: &Path) -> Result<String, String> {
    let root = root
        .to_str()
        .ok_or_else(|| "temporary path is not UTF-8".to_string())?;
    let root = escape(root);
    Ok(format!(
        "(version 1)\n\
         (deny default)\n\
         (deny network*)\n\
         (allow process*)\n\
         (allow sysctl-read)\n\
         (allow file-read-metadata)\n\
         (allow file-read*\n\
         \x20 (literal \"/\")\n\
         \x20 (subpath \"/System\")\n\
         \x20 (subpath \"/usr\")\n\
         \x20 (subpath \"/bin\")\n\
         \x20 (subpath \"/sbin\")\n\
         \x20 (subpath \"/Library/Apple\")\n\
         \x20 (subpath \"{root}\")\n\
         \x20 (literal \"/dev/null\")\n\
         \x20 (literal \"/dev/zero\")\n\
         \x20 (literal \"/dev/random\")\n\
         \x20 (literal \"/dev/urandom\"))\n\
         (allow file-write*\n\
         \x20 (subpath \"{root}\")\n\
         \x20 (literal \"/dev/null\")\n\
         \x20 (literal \"/dev/stdout\")\n\
         \x20 (literal \"/dev/stderr\"))\n"
    ))
}

fn escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            control if control.is_control() => escaped.push('?'),
            other => escaped.push(other),
        }
    }
    escaped
}

fn print_usage() {
    eprintln!(
        "usage: runne-sandbox-helper --self-test\n\
         \x20      runne-sandbox-helper --profile-fd FD [--cwd-fd FD] -- PROGRAM [ARG...]"
    );
}

struct RemoveDir(PathBuf);

impl Drop for RemoveDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
