//! Foreground-terminal secret input for provider credential enrollment.
//!
//! The key is read from a real terminal, never a pipe or redirected file:
//! standard input is rejected unless it is a TTY. Crossterm raw mode disables
//! echo for the duration, and the bytes live only in a zeroizing buffer until
//! the native store takes ownership.

use std::io::{IsTerminal, Write};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal;
use runne_secure_store::{
    MAX_PROVIDER_CREDENTIAL_BYTES, ProviderCredentialId, ProviderCredentialMaterial,
};
use zeroize::Zeroizing;

use crate::CliError;

const MAX_SECRET_BYTES: usize = MAX_PROVIDER_CREDENTIAL_BYTES;

/// Reads one provider key from the foreground terminal without echo.
///
/// # Errors
///
/// Returns [`CliError::CredentialRequiresTerminal`] when standard input is not
/// a terminal, or a closed credential error for empty/oversized/cancelled
/// input. The entered bytes are never echoed, logged, or placed in argv.
pub(crate) fn read_provider_credential(
    provider: ProviderCredentialId,
) -> Result<ProviderCredentialMaterial, CliError> {
    if !std::io::stdin().is_terminal() {
        return Err(CliError::CredentialRequiresTerminal);
    }
    terminal::enable_raw_mode().map_err(|_| CliError::CredentialRequiresTerminal)?;
    let mut guard = RawModeGuard;
    let mut stderr = std::io::stderr();
    write!(
        stderr,
        "{} API key (input hidden): ",
        provider_label(provider)
    )
    .map_err(|_| CliError::CredentialRequiresTerminal)?;
    stderr
        .flush()
        .map_err(|_| CliError::CredentialRequiresTerminal)?;
    let result = read_hidden();
    guard.restore();
    let _ = writeln!(stderr);
    let _ = stderr.flush();
    result.and_then(|secret| {
        ProviderCredentialMaterial::from_zeroizing(secret)
            .map_err(|_| CliError::CredentialOperation)
    })
}

const fn provider_label(provider: ProviderCredentialId) -> &'static str {
    match provider {
        ProviderCredentialId::OpenAi => "OpenAI",
        ProviderCredentialId::DeepSeek => "DeepSeek",
        _ => "Provider",
    }
}

fn read_hidden() -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut secret = Zeroizing::new(Vec::with_capacity(64));
    loop {
        match event::read().map_err(|_| CliError::CredentialOperation)? {
            Event::Key(key) if key.kind != KeyEventKind::Release => match key.code {
                KeyCode::Enter => break,
                KeyCode::Esc => return Err(CliError::CredentialOperation),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Err(CliError::CredentialOperation);
                }
                KeyCode::Backspace => {
                    secret.pop();
                }
                KeyCode::Char(character) if !character.is_control() => {
                    let mut encoded = [0_u8; 4];
                    for byte in character.encode_utf8(&mut encoded).bytes() {
                        if secret.len() >= MAX_SECRET_BYTES {
                            return Err(CliError::CredentialOperation);
                        }
                        secret.push(byte);
                    }
                }
                _ => {}
            },
            Event::Paste(text) => {
                for byte in text.bytes() {
                    if secret.len() >= MAX_SECRET_BYTES {
                        return Err(CliError::CredentialOperation);
                    }
                    secret.push(byte);
                }
            }
            _ => {}
        }
    }
    if secret.is_empty() {
        return Err(CliError::CredentialOperation);
    }
    Ok(secret)
}

struct RawModeGuard;

impl RawModeGuard {
    fn restore(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        self.restore();
    }
}
