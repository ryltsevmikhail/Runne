use crate::OAuthProvider;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use std::fmt;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAX_TOKEN: usize = 16 * 1024;
const MAX_ACCOUNT: usize = 256;

/// Redacted OAuth material suitable for handoff to a secure credential broker.
pub struct CredentialEnvelope {
    provider: OAuthProvider,
    access_token: Zeroizing<String>,
    refresh_token: Option<Zeroizing<String>>,
    account_id: Option<String>,
    credential_version: u64,
    expires_at_unix_seconds: u64,
}

impl fmt::Debug for CredentialEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialEnvelope")
            .field("provider", &self.provider)
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("account_id", &self.account_id)
            .field("credential_version", &self.credential_version)
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish()
    }
}

/// Safe parser or envelope construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CredentialError {
    /// A token is absent, oversized or contains control bytes.
    #[error("invalid OAuth token")]
    Token,
    /// Account identity is malformed.
    #[error("invalid OAuth account id")]
    Account,
    /// Expiry is invalid.
    #[error("invalid OAuth expiry")]
    Expiry,
    /// JSON or JWT payload does not match the provider schema.
    #[error("invalid OAuth response")]
    Response,
    /// The envelope is bound to another provider or credential version.
    #[error("OAuth credential binding mismatch")]
    Binding,
    /// The access token is expired or inside the caller's safety skew.
    #[error("OAuth credential is expired")]
    Expired,
}

impl CredentialEnvelope {
    /// Validates and creates an envelope. Tokens are never included in errors or Debug.
    pub fn new(
        provider: OAuthProvider,
        access: impl Into<String>,
        refresh: Option<String>,
        account: Option<String>,
        expires_at: u64,
    ) -> Result<Self, CredentialError> {
        let access = validate_token(Zeroizing::new(access.into()))?;
        let refresh = refresh
            .map(|value| validate_token(Zeroizing::new(value)))
            .transpose()?;
        let account_id = account.map(validate_account).transpose()?;
        if expires_at == 0 {
            return Err(CredentialError::Expiry);
        }
        Ok(Self {
            provider,
            access_token: access,
            refresh_token: refresh,
            account_id,
            credential_version: 0,
            expires_at_unix_seconds: expires_at,
        })
    }

    pub(crate) fn new_versioned(
        provider: OAuthProvider,
        version: u64,
        access: String,
        refresh: Option<String>,
        account: Option<String>,
        expires_at: u64,
    ) -> Result<Self, CredentialError> {
        if version == 0 {
            return Err(CredentialError::Binding);
        }
        let mut envelope = Self::new(provider, access, refresh, account, expires_at)?;
        envelope.credential_version = version;
        Ok(envelope)
    }
    /// Provider binding.
    pub const fn provider(&self) -> OAuthProvider {
        self.provider
    }
    /// Access token for immediate broker materialization.
    pub fn access_token(&self) -> &str {
        self.access_token.as_str()
    }
    /// Refresh token, when the flow supplied one.
    pub fn refresh_token(&self) -> Option<&str> {
        self.refresh_token.as_deref().map(String::as_str)
    }
    /// Optional provider account identity.
    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }
    /// Credential version bound by secure enrollment; zero means an OAuth flow result
    /// that has not yet been attached to a durable credential version.
    pub const fn credential_version(&self) -> u64 {
        self.credential_version
    }
    /// Absolute expiry in Unix seconds.
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
    /// Returns true when token is expired or within the caller's safety skew.
    pub fn is_expired(&self, now: u64, skew: u64) -> bool {
        now.saturating_add(skew) >= self.expires_at_unix_seconds
    }
}

#[derive(Deserialize)]
struct CodexToken {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}
#[derive(Deserialize)]
struct GithubToken {
    access_token: String,
}
#[derive(Deserialize)]
struct CopilotToken {
    token: String,
    expires_at: u64,
}

impl Drop for CodexToken {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}
impl Drop for GithubToken {
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}
impl Drop for CopilotToken {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// Parses an OpenAI authorization-code or refresh response.
pub fn parse_codex_token(
    json: &[u8],
    now_unix_seconds: u64,
) -> Result<CredentialEnvelope, CredentialError> {
    let mut raw: CodexToken =
        serde_json::from_slice(json).map_err(|_| CredentialError::Response)?;
    let expiry = now_unix_seconds
        .checked_add(raw.expires_in)
        .ok_or(CredentialError::Expiry)?;
    CredentialEnvelope::new(
        OAuthProvider::OpenAiCodex,
        std::mem::take(&mut raw.access_token),
        Some(std::mem::take(&mut raw.refresh_token)),
        None,
        expiry,
    )
}
/// Parses GitHub's device OAuth response. The GitHub token itself is not a Copilot session token.
pub fn parse_github_oauth(
    json: &[u8],
    now_unix_seconds: u64,
    lifetime_seconds: u64,
) -> Result<CredentialEnvelope, CredentialError> {
    let mut raw: GithubToken =
        serde_json::from_slice(json).map_err(|_| CredentialError::Response)?;
    let expiry = now_unix_seconds
        .checked_add(lifetime_seconds)
        .ok_or(CredentialError::Expiry)?;
    CredentialEnvelope::new(
        OAuthProvider::GithubCopilot,
        std::mem::take(&mut raw.access_token),
        None,
        None,
        expiry,
    )
}
/// Parses a Copilot session exchange response (`token`, `expires_at`).
pub fn parse_copilot_session(
    json: &[u8],
    refresh: String,
) -> Result<CredentialEnvelope, CredentialError> {
    let mut raw: CopilotToken =
        serde_json::from_slice(json).map_err(|_| CredentialError::Response)?;
    CredentialEnvelope::new(
        OAuthProvider::GithubCopilot,
        std::mem::take(&mut raw.token),
        Some(refresh),
        None,
        raw.expires_at,
    )
}

/// Untrusted account claim extracted from a JWT payload; auth service must verify it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UntrustedAccountClaim {
    /// Claimed account id.
    pub account_id: String,
}

/// Extracts the Codex account claim without validating JWT signature or issuer.
pub fn extract_untrusted_codex_account_claim(
    token: &str,
) -> Result<UntrustedAccountClaim, CredentialError> {
    let payload = token.split('.').nth(1).ok_or(CredentialError::Response)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| CredentialError::Response)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| CredentialError::Response)?;
    let account = value
        .get("https://api.openai.com/auth")
        .and_then(|v| v.get("chatgpt_account_id"))
        .and_then(serde_json::Value::as_str)
        .ok_or(CredentialError::Response)?;
    Ok(UntrustedAccountClaim {
        account_id: validate_account(account.to_owned())?,
    })
}

fn validate_token(value: Zeroizing<String>) -> Result<Zeroizing<String>, CredentialError> {
    if value.is_empty() || value.len() > MAX_TOKEN || value.chars().any(char::is_control) {
        return Err(CredentialError::Token);
    }
    Ok(value)
}
fn validate_account(value: String) -> Result<String, CredentialError> {
    if value.is_empty()
        || value.len() > MAX_ACCOUNT
        || value.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(CredentialError::Account);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_separate_codex_and_copilot_shapes() {
        let codex = parse_codex_token(br#"{"access_token":"secret-access","refresh_token":"secret-refresh","expires_in":3600}"#, 100).unwrap();
        assert_eq!(codex.provider(), OAuthProvider::OpenAiCodex);
        assert!(!codex.is_expired(100, 60));
        assert!(format!("{codex:?}").contains("REDACTED"));
        assert!(!format!("{codex:?}").contains("secret-access"));
        let copilot =
            parse_copilot_session(br#"{"token":"session","expires_at":500}"#, "refresh".into())
                .unwrap();
        assert_eq!(copilot.provider(), OAuthProvider::GithubCopilot);
        assert!(copilot.is_expired(500, 0));
        let github = parse_github_oauth(br#"{"access_token":"github"}"#, 100, 60).unwrap();
        assert_eq!(github.access_token(), "github");
        assert!(parse_copilot_session(br#"{"access_token":"github"}"#, "r".into()).is_err());
    }
    #[test]
    fn jwt_claim_is_explicitly_untrusted() {
        let payload = URL_SAFE_NO_PAD
            .encode(br#"{"https://api.openai.com/auth":{"chatgpt_account_id":"acct"}}"#);
        let token = format!("x.{payload}.y");
        assert_eq!(
            extract_untrusted_codex_account_claim(&token)
                .unwrap()
                .account_id,
            "acct"
        );
        assert!(CredentialEnvelope::new(OAuthProvider::OpenAiCodex, "x\n", None, None, 1).is_err());
    }
}
