use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use runne_platform_ports::provider_credential_prompt::{
    CredentialPromptAction, CredentialPromptProvider, SecureCredentialMaterial,
    SecureCredentialPromptDisposition, SecureCredentialPromptError, SecureCredentialPromptPort,
    SecureCredentialPromptRequest,
};
use zeroize::Zeroizing;

const MAX_PROMPT_SECONDS: u64 = 30;
const MAX_PINENTRY_RESPONSE_BYTES: usize = 8 * 1024;

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
        let disposition = decode_pinentry_response(&response)?;
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
    let provider = match request.provider() {
        CredentialPromptProvider::OpenAi => "OpenAI",
        CredentialPromptProvider::DeepSeek => "DeepSeek",
    };
    let action = match request.action() {
        CredentialPromptAction::Pair => "add",
        CredentialPromptAction::Rotate => "rotate",
        CredentialPromptAction::MigrateLegacy => "migrate",
    };
    format!(
        "SETTITLE GOCODE provider credential\nSETDESC Enter {provider} credential to {action} revision {}\nGETPIN\n",
        request.expected_revision()
    )
}

pub(super) fn decode_pinentry_response(
    response: &[u8],
) -> Result<SecureCredentialPromptDisposition, SecureCredentialPromptError> {
    let mut data = None;
    for line in response.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(encoded) = line.strip_prefix(b"D ") {
            if data.replace(encoded).is_some() {
                return Err(SecureCredentialPromptError::Rejected);
            }
        } else if line.starts_with(b"ERR ") {
            return if line
                .windows(b"canceled".len())
                .any(|part| part == b"canceled")
            {
                Ok(SecureCredentialPromptDisposition::Cancelled)
            } else {
                Err(SecureCredentialPromptError::Unavailable)
            };
        }
    }
    let data = data.ok_or(SecureCredentialPromptError::Rejected)?;
    let decoded = decode_percent(data)?;
    SecureCredentialMaterial::new(decoded.to_vec())
        .map(SecureCredentialPromptDisposition::Submitted)
}

fn decode_percent(value: &[u8]) -> Result<Zeroizing<Vec<u8>>, SecureCredentialPromptError> {
    let mut decoded = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut position = 0;
    while position < value.len() {
        if value[position] == b'%' {
            let high = value
                .get(position + 1)
                .ok_or(SecureCredentialPromptError::Rejected)?;
            let low = value
                .get(position + 2)
                .ok_or(SecureCredentialPromptError::Rejected)?;
            decoded.push((hex(*high)? << 4) | hex(*low)?);
            position += 3;
        } else {
            decoded.push(value[position]);
            position += 1;
        }
    }
    Ok(decoded)
}

const fn hex(value: u8) -> Result<u8, SecureCredentialPromptError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(SecureCredentialPromptError::Rejected),
    }
}
