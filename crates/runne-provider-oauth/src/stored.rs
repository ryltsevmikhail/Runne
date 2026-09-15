use crate::{CredentialEnvelope, CredentialError, OAuthProvider};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const MAX_ENVELOPE: usize = 32 * 1024;
const ENVELOPE_SCHEMA: &str = "runne.oauth-credential/v1";
const IMPORT_SCHEMA: &str = "runne.oauth-import/v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredOAuthEnvelope {
    schema: String,
    provider: String,
    credential_version: u64,
    #[serde(deserialize_with = "deserialize_token")]
    access_token: Zeroizing<String>,
    #[serde(deserialize_with = "deserialize_optional_token")]
    refresh_token: Option<Zeroizing<String>>,
    account_id: Option<String>,
    expires_at_unix_seconds: u64,
}

#[derive(Serialize)]
struct StoredOAuthEnvelopeRef<'a> {
    schema: &'static str,
    provider: &'static str,
    credential_version: u64,
    access_token: &'a str,
    refresh_token: Option<&'a str>,
    account_id: Option<&'a str>,
    expires_at_unix_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthImportEnvelope {
    schema: String,
    provider: String,
    #[serde(deserialize_with = "deserialize_token")]
    access_token: Zeroizing<String>,
    #[serde(deserialize_with = "deserialize_optional_token")]
    refresh_token: Option<Zeroizing<String>>,
    account_id: Option<String>,
    expires_at_unix_seconds: u64,
}

impl Drop for OAuthImportEnvelope {
    fn drop(&mut self) {
        self.schema.zeroize();
        self.provider.zeroize();
        self.access_token.zeroize();
        if let Some(refresh) = &mut self.refresh_token {
            refresh.zeroize();
        }
    }
}

fn deserialize_token<'de, D>(deserializer: D) -> Result<Zeroizing<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    String::deserialize(deserializer).map(Zeroizing::new)
}

fn deserialize_optional_token<'de, D>(
    deserializer: D,
) -> Result<Option<Zeroizing<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(|value| value.map(Zeroizing::new))
}

impl Drop for StoredOAuthEnvelope {
    fn drop(&mut self) {
        self.schema.zeroize();
        self.provider.zeroize();
        self.access_token.zeroize();
        if let Some(refresh) = &mut self.refresh_token {
            refresh.zeroize();
        }
    }
}

/// Parses the exact secure-store handoff envelope after the broker authorizes
/// a read. The receipt supplies provider and version; expired or mismatched
/// material cannot reach an HTTP adapter.
pub fn parse_stored_envelope(
    json: &[u8],
    expected_provider: OAuthProvider,
    expected_version: u64,
    now_unix_seconds: u64,
    skew_seconds: u64,
) -> Result<CredentialEnvelope, CredentialError> {
    if json.is_empty() || json.len() > MAX_ENVELOPE || expected_version == 0 {
        return Err(CredentialError::Binding);
    }
    let mut raw: StoredOAuthEnvelope =
        serde_json::from_slice(json).map_err(|_| CredentialError::Response)?;
    let provider = match (raw.provider.as_str(), expected_provider) {
        ("openai-codex", OAuthProvider::OpenAiCodex) => OAuthProvider::OpenAiCodex,
        ("github-copilot", OAuthProvider::GithubCopilot) => OAuthProvider::GithubCopilot,
        _ => return Err(CredentialError::Binding),
    };
    if raw.schema != ENVELOPE_SCHEMA || raw.credential_version != expected_version {
        return Err(CredentialError::Binding);
    }
    let envelope = CredentialEnvelope::new_versioned(
        provider,
        raw.credential_version,
        raw.access_token.as_str().to_owned(),
        raw.refresh_token
            .take()
            .map(|value| value.as_str().to_owned()),
        raw.account_id.take(),
        raw.expires_at_unix_seconds,
    )?;
    if envelope.is_expired(now_unix_seconds, skew_seconds) {
        return Err(CredentialError::Expired);
    }
    if provider == OAuthProvider::OpenAiCodex && envelope.account_id().is_none() {
        return Err(CredentialError::Binding);
    }
    Ok(envelope)
}

/// Parses the unversioned native capture before Pair admission assigns the
/// protected credential version. The capture schema intentionally has no
/// caller-controlled version field.
pub fn parse_unversioned_import(
    json: &[u8],
    expected_provider: OAuthProvider,
    admitted_version: u64,
    now_unix_seconds: u64,
    skew_seconds: u64,
) -> Result<CredentialEnvelope, CredentialError> {
    if json.is_empty() || json.len() > MAX_ENVELOPE || admitted_version == 0 {
        return Err(CredentialError::Binding);
    }
    let mut raw: OAuthImportEnvelope =
        serde_json::from_slice(json).map_err(|_| CredentialError::Response)?;
    let provider = match (raw.provider.as_str(), expected_provider) {
        ("openai-codex", OAuthProvider::OpenAiCodex) => OAuthProvider::OpenAiCodex,
        ("github-copilot", OAuthProvider::GithubCopilot) => OAuthProvider::GithubCopilot,
        _ => return Err(CredentialError::Binding),
    };
    if raw.schema != IMPORT_SCHEMA {
        return Err(CredentialError::Binding);
    }
    let envelope = CredentialEnvelope::new_versioned(
        provider,
        admitted_version,
        raw.access_token.as_str().to_owned(),
        raw.refresh_token
            .take()
            .map(|value| value.as_str().to_owned()),
        raw.account_id.take(),
        raw.expires_at_unix_seconds,
    )?;
    if envelope.is_expired(now_unix_seconds, skew_seconds) {
        return Err(CredentialError::Expired);
    }
    if provider == OAuthProvider::OpenAiCodex && envelope.account_id().is_none() {
        return Err(CredentialError::Binding);
    }
    Ok(envelope)
}

/// Serializes an OAuth result for the broker using the admitted credential version.
///
/// The caller must pass the version allocated by the protected Pair command; a
/// version embedded in an untrusted OAuth response is never accepted here.
pub fn encode_stored_envelope(
    envelope: &CredentialEnvelope,
    admitted_version: u64,
) -> Result<Zeroizing<Vec<u8>>, CredentialError> {
    if admitted_version == 0 {
        return Err(CredentialError::Binding);
    }
    let provider = match envelope.provider() {
        OAuthProvider::OpenAiCodex => "openai-codex",
        OAuthProvider::GithubCopilot => "github-copilot",
    };
    let value = StoredOAuthEnvelopeRef {
        schema: ENVELOPE_SCHEMA,
        provider,
        credential_version: admitted_version,
        access_token: envelope.access_token(),
        refresh_token: envelope.refresh_token(),
        account_id: envelope.account_id(),
        expires_at_unix_seconds: envelope.expires_at_unix_seconds(),
    };
    let bytes = serde_json::to_vec(&value).map_err(|_| CredentialError::Response)?;
    if bytes.is_empty() || bytes.len() > MAX_ENVELOPE {
        return Err(CredentialError::Response);
    }
    Ok(Zeroizing::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binds_provider_version_and_expiry() {
        let json = br#"{"schema":"runne.oauth-credential/v1","provider":"openai-codex","credential_version":7,"access_token":"access","refresh_token":"refresh","account_id":"acct","expires_at_unix_seconds":500}"#;
        let envelope = parse_stored_envelope(json, OAuthProvider::OpenAiCodex, 7, 100, 60).unwrap();
        assert_eq!(envelope.credential_version(), 7);
        assert_eq!(envelope.account_id(), Some("acct"));
        assert_eq!(envelope.access_token(), "access");
        assert!(matches!(
            parse_stored_envelope(json, OAuthProvider::OpenAiCodex, 8, 100, 60),
            Err(CredentialError::Binding)
        ));
        assert!(matches!(
            parse_stored_envelope(json, OAuthProvider::OpenAiCodex, 7, 450, 60),
            Err(CredentialError::Expired)
        ));
    }

    #[test]
    fn keeps_copilot_separate_and_rejects_shape_drift() {
        let json = br#"{"schema":"runne.oauth-credential/v1","provider":"github-copilot","credential_version":2,"access_token":"session","refresh_token":null,"account_id":null,"expires_at_unix_seconds":500}"#;
        let envelope =
            parse_stored_envelope(json, OAuthProvider::GithubCopilot, 2, 100, 0).unwrap();
        assert_eq!(envelope.provider(), OAuthProvider::GithubCopilot);
        assert!(envelope.account_id().is_none());
        let mut unknown = json.to_vec();
        unknown.pop();
        unknown.extend_from_slice(br#",\"extra\":true}"#);
        assert!(matches!(
            parse_stored_envelope(&unknown, OAuthProvider::GithubCopilot, 2, 100, 0),
            Err(CredentialError::Response)
        ));
    }

    #[test]
    fn storage_encoder_stamps_admitted_version_and_supports_full_envelope_bound() {
        let envelope = CredentialEnvelope::new(
            OAuthProvider::GithubCopilot,
            "access",
            Some("refresh".to_owned()),
            None,
            500,
        )
        .unwrap();
        let bytes = encode_stored_envelope(&envelope, 9).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["credential_version"], 9);
        assert!(parse_stored_envelope(&bytes, OAuthProvider::GithubCopilot, 9, 100, 0).is_ok());
        assert!(matches!(
            encode_stored_envelope(&envelope, 0),
            Err(CredentialError::Binding)
        ));
    }

    #[test]
    fn unversioned_import_uses_each_admitted_version_and_rejects_version_field() {
        let json = br#"{"schema":"runne.oauth-import/v1","provider":"github-copilot","access_token":"session","refresh_token":null,"account_id":null,"expires_at_unix_seconds":500}"#;
        for version in [7, 8] {
            let envelope =
                parse_unversioned_import(json, OAuthProvider::GithubCopilot, version, 100, 0)
                    .unwrap();
            assert_eq!(envelope.credential_version(), version);
        }
        let with_version = br#"{"schema":"runne.oauth-import/v1","provider":"github-copilot","credential_version":7,"access_token":"session","refresh_token":null,"account_id":null,"expires_at_unix_seconds":500}"#;
        assert!(matches!(
            parse_unversioned_import(with_version, OAuthProvider::GithubCopilot, 8, 100, 0),
            Err(CredentialError::Response)
        ));
    }
}
