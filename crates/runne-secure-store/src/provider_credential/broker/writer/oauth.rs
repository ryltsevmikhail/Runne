use runne_provider_oauth::{
    CredentialError, OAuthProvider, encode_stored_envelope, parse_unversioned_import,
};
use zeroize::Zeroizing;

use crate::SecureStoreError;

/// Re-encodes an unversioned OAuth capture with the version allocated by the
/// exact Pair target. The capture cannot supply or override that version.
pub(super) fn canonicalize(
    provider: &str,
    version: u64,
    secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
    let expected = match provider {
        "openai-codex" => OAuthProvider::OpenAiCodex,
        "github-copilot" => OAuthProvider::GithubCopilot,
        _ => return Err(SecureStoreError::CredentialAccessDenied),
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| SecureStoreError::InvalidProviderCredential)?
        .as_secs();
    let envelope =
        parse_unversioned_import(secret, expected, version, now, 60).map_err(map_oauth_error)?;
    encode_stored_envelope(&envelope, version).map_err(map_oauth_error)
}

const fn map_oauth_error(error: CredentialError) -> SecureStoreError {
    match error {
        CredentialError::Binding | CredentialError::Expired => {
            SecureStoreError::CredentialAccessDenied
        }
        CredentialError::Token
        | CredentialError::Account
        | CredentialError::Expiry
        | CredentialError::Response => SecureStoreError::InvalidProviderCredential,
    }
}

#[cfg(test)]
mod tests {
    use super::canonicalize;

    #[test]
    fn one_unversioned_capture_gets_the_exact_pair_or_rotate_version() {
        let capture = br#"{"schema":"runne.oauth-import/v1","provider":"github-copilot","access_token":"session","refresh_token":null,"account_id":null,"expires_at_unix_seconds":4000000000}"#;
        let pair = canonicalize("github-copilot", 7, capture).unwrap();
        let rotate = canonicalize("github-copilot", 8, capture).unwrap();
        let pair: serde_json::Value = serde_json::from_slice(&pair).unwrap();
        let rotate: serde_json::Value = serde_json::from_slice(&rotate).unwrap();
        assert_eq!(pair["credential_version"], 7);
        assert_eq!(rotate["credential_version"], 8);
    }
}
