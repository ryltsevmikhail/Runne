//! GUI pinentry host prompt with a hardened child lifecycle (P1/P2).
//!
//! Reuses the crate's pinentry protocol decoder on top of a GUI-only
//! environment allowlist: the child receives exactly the non-secret GUI
//! connectivity variables (copied by name from this process), never the full
//! environment. Missing GUI variables or a missing absolute binary reject
//! with `Unavailable` BEFORE any process is spawned (no tty fallback). The
//! parent owns a wall-clock deadline: a hung child is killed and reaped by
//! the parent — pinentry's own `--timeout` is never the process boundary.
//! Secret material stays inside `Zeroizing` Rust types on this side of the
//! boundary; the renderer never observes it.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use std::{io, thread};

use runne_platform_ports::provider_credential_prompt::{
    CredentialPromptAction, MAX_NATIVE_OAUTH_CREDENTIAL_BYTES, SecureCredentialPromptDisposition,
    SecureCredentialPromptError, SecureCredentialPromptPort, SecureCredentialPromptRequest,
};
use zeroize::Zeroizing;

use super::pinentry_protocol::decode_pinentry_response;

/// Non-secret GUI connectivity variables copied by name into the child.
pub const GUI_ENV_ALLOWLIST: [&str; 7] = [
    "WAYLAND_DISPLAY",
    "DISPLAY",
    "XDG_RUNTIME_DIR",
    "XDG_SESSION_TYPE",
    "XDG_CURRENT_DESKTOP",
    "DBUS_SESSION_BUS_ADDRESS",
    "XAUTHORITY",
];

const MAX_PROMPT_SECONDS: u64 = 30;
const MAX_DEADLINE_SECONDS: u64 = 60;
const MAX_RESPONSE_BYTES: usize = 3 * MAX_NATIVE_OAUTH_CREDENTIAL_BYTES + 256;

pub struct LinuxGuiHostCredentialPrompt {
    executable: PathBuf,
    pinentry_timeout: Duration,
    wall_deadline: Duration,
}

impl LinuxGuiHostCredentialPrompt {
    /// Creates the GUI prompt adapter; rejects relative binaries and
    /// unbounded or inconsistent timeouts.
    ///
    /// # Errors
    ///
    /// Returns [`SecureCredentialPromptError::Rejected`] for relative paths
    /// or invalid timeout combinations.
    pub fn new(
        executable: PathBuf,
        pinentry_timeout: Duration,
        wall_deadline: Duration,
    ) -> Result<Self, SecureCredentialPromptError> {
        if !executable.is_absolute()
            || pinentry_timeout.is_zero()
            || pinentry_timeout > Duration::from_secs(MAX_PROMPT_SECONDS)
            || wall_deadline.is_zero()
            || wall_deadline > Duration::from_secs(MAX_DEADLINE_SECONDS)
        {
            return Err(SecureCredentialPromptError::Rejected);
        }
        Ok(Self {
            executable,
            pinentry_timeout,
            wall_deadline,
        })
    }

    /// Absolute pinentry binary path used for this adapter.
    #[must_use]
    pub fn executable(&self) -> &std::path::Path {
        &self.executable
    }

    /// Runs the prompt with GUI variables copied from this process.
    ///
    /// # Errors
    ///
    /// Fails closed before spawn when no GUI variable set is present.
    pub fn prompt(
        &mut self,
        request: SecureCredentialPromptRequest,
    ) -> Result<SecureCredentialPromptDisposition, SecureCredentialPromptError> {
        self.prompt_with_env(
            request,
            &collect_gui_environment(|name| std::env::var_os(name)),
        )
    }

    /// Runs the prompt against one explicit environment snapshot (tests).
    ///
    /// # Errors
    ///
    /// Returns [`SecureCredentialPromptError::Unavailable`] before spawn when
    /// neither `DISPLAY` nor `WAYLAND_DISPLAY` is present.
    pub fn prompt_with_env(
        &mut self,
        request: SecureCredentialPromptRequest,
        environment: &[(String, std::ffi::OsString)],
    ) -> Result<SecureCredentialPromptDisposition, SecureCredentialPromptError> {
        let has_gui = environment.iter().any(|(name, value)| {
            (name == "DISPLAY" || name == "WAYLAND_DISPLAY") && !value.is_empty()
        });
        if !has_gui {
            return Err(SecureCredentialPromptError::Unavailable);
        }
        let deadline = Instant::now() + self.wall_deadline;
        let mut child = self.spawn(environment)?;
        if let Some(stdin) = child.stdin.as_mut()
            && stdin.write_all(prompt_command(request).as_bytes()).is_err()
        {
            return Err(kill_and_reap(&mut child));
        }
        drop(child.stdin.take());
        let mut stdout = child
            .stdout
            .take()
            .ok_or(SecureCredentialPromptError::Unavailable)?;
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut response = Zeroizing::new(Vec::new());
            let mut chunk = [0_u8; 4096];
            let outcome = loop {
                match stdout.read(&mut chunk) {
                    Ok(0) => break Ok(()),
                    Ok(read) => {
                        response.extend_from_slice(&chunk[..read]);
                        if response.len() > MAX_RESPONSE_BYTES {
                            break Err(SecureCredentialPromptError::Rejected);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => break Err(SecureCredentialPromptError::Unavailable),
                }
            };
            let _ = sender.send((outcome, response));
        });
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Ok((outcome, response)) = receiver.recv_timeout(remaining) else {
            return Err(kill_and_reap(&mut child));
        };
        if outcome.is_err() {
            return Err(kill_and_reap(&mut child));
        }
        let status = wait_for_exit_until(&mut child, deadline)?;
        let disposition =
            decode_pinentry_response(request.provider(), request.action(), &response)?;
        if status.success() || matches!(disposition, SecureCredentialPromptDisposition::Cancelled) {
            Ok(disposition)
        } else {
            Err(SecureCredentialPromptError::Unavailable)
        }
    }

    fn spawn(
        &self,
        environment: &[(String, std::ffi::OsString)],
    ) -> Result<Child, SecureCredentialPromptError> {
        Command::new(&self.executable)
            .arg("--timeout")
            .arg(self.pinentry_timeout.as_secs().to_string())
            .env_clear()
            .envs(environment.iter().map(|(name, value)| (name, value)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| SecureCredentialPromptError::Unavailable)
    }
}

fn wait_for_exit_until(
    child: &mut Child,
    deadline: Instant,
) -> Result<ExitStatus, SecureCredentialPromptError> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(_) => return Err(kill_and_reap(child)),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(kill_and_reap(child));
        }
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

/// Copies exactly the GUI allowlist variables from one named source.
///
/// This is the production environment seam: the child can never receive a
/// variable that is not named in [`GUI_ENV_ALLOWLIST`], regardless of what
/// the parent process carries.
pub fn collect_gui_environment(
    source: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Vec<(String, std::ffi::OsString)> {
    GUI_ENV_ALLOWLIST
        .iter()
        .filter_map(|name| source(name).map(|value| ((*name).to_owned(), value)))
        .collect()
}

fn kill_and_reap(child: &mut Child) -> SecureCredentialPromptError {
    let _ = child.kill();
    let _ = child.wait();
    SecureCredentialPromptError::Unavailable
}

impl SecureCredentialPromptPort for LinuxGuiHostCredentialPrompt {
    fn prompt(
        &mut self,
        request: SecureCredentialPromptRequest,
    ) -> Result<SecureCredentialPromptDisposition, SecureCredentialPromptError> {
        Self::prompt(self, request)
    }
}

fn prompt_command(request: SecureCredentialPromptRequest) -> String {
    let provider = request.provider().label();
    let action = match request.action() {
        CredentialPromptAction::Pair => "add",
        CredentialPromptAction::Rotate => "rotate",
        CredentialPromptAction::Revoke => "revoke",
        CredentialPromptAction::MigrateLegacy => "migrate",
        CredentialPromptAction::Verify => "verify",
    };
    let command = if request.action().requires_secret() {
        "GETPIN"
    } else {
        "CONFIRM"
    };
    let verb = if request.action().requires_secret() {
        "Enter"
    } else {
        "Confirm"
    };
    format!(
        "SETTITLE GOCODE provider credential\nSETDESC {verb} {provider} credential to {action} revision {}\n{command}\n",
        request.expected_revision()
    )
}

#[cfg(test)]
#[path = "linux_gui_error_tests.rs"]
mod error_tests;
#[cfg(test)]
#[path = "linux_gui_tests.rs"]
mod tests;
