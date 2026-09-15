use runne_platform_ports::provider_credential_prompt::{
    CredentialPromptAction, CredentialPromptProvider, SecureCredentialMaterial,
    SecureCredentialPromptDisposition, SecureCredentialPromptError,
};
use zeroize::Zeroizing;

pub(super) fn decode_pinentry_response(
    provider: CredentialPromptProvider,
    action: CredentialPromptAction,
    response: &[u8],
) -> Result<SecureCredentialPromptDisposition, SecureCredentialPromptError> {
    if !response.ends_with(b"\n") {
        return Err(SecureCredentialPromptError::Rejected);
    }
    let mut acknowledgement = 0_u8;
    let mut data = None;
    let mut terminal = None;
    for line in response[..response.len() - 1].split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if terminal.is_some() || line.is_empty() {
            return Err(SecureCredentialPromptError::Rejected);
        }
        if acknowledgement < 3 {
            if is_ok(line) {
                acknowledgement += 1;
                continue;
            }
            return Err(SecureCredentialPromptError::Unavailable);
        }
        if let Some(encoded) = line.strip_prefix(b"D ") {
            if !action.requires_secret() || data.replace(encoded).is_some() {
                return Err(SecureCredentialPromptError::Rejected);
            }
        } else if line.starts_with(b"ERR ") {
            terminal = Some(if line.windows(8).any(|part| part == b"canceled") {
                Ok(SecureCredentialPromptDisposition::Cancelled)
            } else {
                Err(SecureCredentialPromptError::Unavailable)
            });
        } else if is_ok(line) {
            terminal = Some(terminal_success(provider, action, data.take()));
        } else {
            return Err(SecureCredentialPromptError::Rejected);
        }
    }
    terminal.ok_or(SecureCredentialPromptError::Rejected)?
}

fn terminal_success(
    provider: CredentialPromptProvider,
    action: CredentialPromptAction,
    data: Option<&[u8]>,
) -> Result<SecureCredentialPromptDisposition, SecureCredentialPromptError> {
    if action.requires_secret() {
        let decoded = decode_percent(data.ok_or(SecureCredentialPromptError::Rejected)?)?;
        SecureCredentialMaterial::from_zeroizing_for_provider(provider, decoded)
            .map(SecureCredentialPromptDisposition::Submitted)
    } else if data.is_none() {
        Ok(SecureCredentialPromptDisposition::Confirmed)
    } else {
        Err(SecureCredentialPromptError::Rejected)
    }
}

fn is_ok(line: &[u8]) -> bool {
    line == b"OK" || line.starts_with(b"OK ")
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
