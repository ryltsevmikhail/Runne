use std::io::Read;

use runne_secure_store::{MAX_PROVIDER_CREDENTIAL_BYTES, ProviderCredentialMaterial};
use zeroize::Zeroizing;

use super::CliError;

/// Parses exactly one bounded credential line for the consuming claim state.
///
/// The returned material remains zeroizing. Any partial, invalid, oversized,
/// or trailing input fails before a native writer effect can begin.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the authenticated inherited-channel runner is composed after the platform handoff"
    )
)]
pub fn read_secret_line(reader: &mut impl Read) -> Result<ProviderCredentialMaterial, CliError> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PROVIDER_CREDENTIAL_BYTES));
    loop {
        let mut byte = [0_u8; 1];
        if reader
            .read(&mut byte)
            .map_err(|_| CliError::CredentialOperation)?
            != 1
        {
            return Err(CliError::CredentialOperation);
        }
        match byte[0] {
            b'\n' => break,
            0 | b'\r' => return Err(CliError::CredentialOperation),
            value => {
                if bytes.len() == MAX_PROVIDER_CREDENTIAL_BYTES {
                    return Err(CliError::CredentialOperation);
                }
                bytes.push(value);
            }
        }
    }
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|_| CliError::CredentialOperation)?
        != 0
    {
        return Err(CliError::CredentialOperation);
    }
    ProviderCredentialMaterial::new(std::mem::take(&mut *bytes))
        .map_err(|_| CliError::CredentialOperation)
}
