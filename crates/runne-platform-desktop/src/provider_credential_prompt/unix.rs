use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use runne_platform_ports::provider_credential_prompt::{
    CredentialPromptAction, MAX_NATIVE_OAUTH_CREDENTIAL_BYTES, SecureCredentialPromptDisposition,
    SecureCredentialPromptError, SecureCredentialPromptPort, SecureCredentialPromptRequest,
};
use zeroize::Zeroizing;

use super::pinentry_protocol::decode_pinentry_response;

const MAX_PROMPT_SECONDS: u64 = 30;
const MAX_PINENTRY_RESPONSE_BYTES: usize = 3 * MAX_NATIVE_OAUTH_CREDENTIAL_BYTES + 256;

/// Linux host-native credential prompt backed by an injected absolute pinentry binary.
pub struct LinuxPinentryPrompt {
    executable: PathBuf,
    timeout: Duration,
}

impl LinuxPinentryPrompt {
    /// Creates a prompt adapter without consulting `PATH` or renderer state.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for relative paths or an unbounded timeout.
    pub fn new(
        executable: PathBuf,
        timeout: Duration,
    ) -> Result<Self, SecureCredentialPromptError> {
        if !executable.is_absolute()
            || timeout.is_zero()
            || timeout > Duration::from_secs(MAX_PROMPT_SECONDS)
        {
            return Err(SecureCredentialPromptError::Rejected);
        }
        Ok(Self {
            executable,
            timeout,
        })
    }

    #[must_use]
    pub fn executable(&self) -> &Path {
        &self.executable
    }
}

impl SecureCredentialPromptPort for LinuxPinentryPrompt {
    fn prompt(
        &mut self,
        request: SecureCredentialPromptRequest,
    ) -> Result<SecureCredentialPromptDisposition, SecureCredentialPromptError> {
        let seconds = self.timeout.as_secs().to_string();
        let mut child = Command::new(&self.executable)
            .arg("--timeout")
            .arg(seconds)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| SecureCredentialPromptError::Unavailable)?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or(SecureCredentialPromptError::Unavailable)?;
        let command = prompt_command(request);
        if stdin.write_all(command.as_bytes()).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SecureCredentialPromptError::Unavailable);
        }
        drop(stdin);
        let output = child
            .wait_with_output()
            .map_err(|_| SecureCredentialPromptError::Unavailable)?;
        let response = Zeroizing::new(output.stdout);
        if response.len() > MAX_PINENTRY_RESPONSE_BYTES {
            return Err(SecureCredentialPromptError::Rejected);
        }
        let disposition =
            decode_pinentry_response(request.provider(), request.action(), &response)?;
        if output.status.success()
            || matches!(disposition, SecureCredentialPromptDisposition::Cancelled)
        {
            Ok(disposition)
        } else {
            Err(SecureCredentialPromptError::Unavailable)
        }
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
