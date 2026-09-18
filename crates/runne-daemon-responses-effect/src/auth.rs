use bytes::Bytes;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderMap, HeaderValue, USER_AGENT};
use runne_provider_oauth::{CredentialEnvelope, OAuthProvider};
use std::fmt;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Header policy selected by the exact provider profile.
#[derive(Clone, PartialEq, Eq)]
pub enum ResponsesAuth {
    /// Azure OpenAI `api-key` authentication.
    AzureApiKey,
    /// xAI bearer authentication.
    XaiBearer,
    /// Codex bearer authentication with its required account header.
    Codex {
        /// ChatGPT account identity.
        account_id: String,
    },
    /// GitHub Copilot short-lived session bearer authentication.
    CopilotSession,
}

impl fmt::Debug for ResponsesAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AzureApiKey => formatter.write_str("AzureApiKey"),
            Self::XaiBearer => formatter.write_str("XaiBearer"),
            Self::CopilotSession => formatter.write_str("CopilotSession"),
            Self::Codex { .. } => formatter.write_str("Codex { account_id: [REDACTED] }"),
        }
    }
}

/// Authentication configuration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthError {
    /// Credential bytes were not a valid one-line token.
    #[error("credential material is invalid")]
    Credential,
    /// Authentication policy does not match provider.
    #[error("credential policy does not match responses provider")]
    Provider,
}

impl ResponsesAuth {
    /// Validates profile compatibility without looking at credential material.
    pub fn matches_provider_id(&self, id: &str) -> bool {
        matches!(
            (self, id),
            (Self::AzureApiKey, "azure-openai-responses")
                | (Self::XaiBearer, "xai")
                | (Self::Codex { .. }, "openai-codex")
                | (Self::CopilotSession, "github-copilot")
        )
    }
    /// Builds sensitive request headers from a broker-owned token.
    pub fn headers(
        &self,
        credential: &Zeroizing<Vec<u8>>,
        request_id: &str,
    ) -> Result<HeaderMap, AuthError> {
        self.headers_inner(credential, request_id, None)
    }

    /// Builds headers from the exact OAuth envelope read after a dispatch
    /// receipt. Azure and xAI intentionally reject this path because their
    /// configured authentication is an API key or ordinary bearer token. For
    /// Codex, the envelope account is authoritative; the configured account
    /// is only a legacy direct-token fallback and is never mixed into OAuth.
    pub fn headers_from_oauth_envelope(
        &self,
        envelope: &CredentialEnvelope,
        request_id: &str,
    ) -> Result<HeaderMap, AuthError> {
        let expected = match self {
            Self::Codex { .. } => OAuthProvider::OpenAiCodex,
            Self::CopilotSession => OAuthProvider::GithubCopilot,
            Self::AzureApiKey | Self::XaiBearer => return Err(AuthError::Provider),
        };
        if envelope.provider() != expected {
            return Err(AuthError::Provider);
        }
        let account = match self {
            Self::Codex { .. } => Some(envelope.account_id().ok_or(AuthError::Credential)?),
            Self::CopilotSession | Self::AzureApiKey | Self::XaiBearer => None,
        };
        let token = Zeroizing::new(envelope.access_token().as_bytes().to_vec());
        self.headers_inner(&token, request_id, account)
    }

    fn headers_inner(
        &self,
        credential: &Zeroizing<Vec<u8>>,
        request_id: &str,
        account_override: Option<&str>,
    ) -> Result<HeaderMap, AuthError> {
        if credential.is_empty()
            || credential.len() > 16 * 1024
            || credential.iter().any(|b| matches!(b, 0 | b'\r' | b'\n'))
        {
            return Err(AuthError::Credential);
        }
        let mut headers = HeaderMap::new();
        let mut request = HeaderValue::from_str(request_id).map_err(|_| AuthError::Credential)?;
        request.set_sensitive(false);
        headers.insert("x-client-request-id", request);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(USER_AGENT, HeaderValue::from_static("Runne/Responses"));
        match self {
            Self::AzureApiKey => {
                headers.insert("api-key", sensitive_header(credential)?);
            }
            Self::XaiBearer => {
                let bearer =
                    Zeroizing::new([b"Bearer ".as_slice(), credential.as_slice()].concat());
                headers.insert(AUTHORIZATION, sensitive_header(&bearer)?);
            }
            Self::CopilotSession => {
                let bearer =
                    Zeroizing::new([b"Bearer ".as_slice(), credential.as_slice()].concat());
                headers.insert(AUTHORIZATION, sensitive_header(&bearer)?);
                headers.insert("X-Initiator", HeaderValue::from_static("user"));
                headers.insert(
                    "Openai-Intent",
                    HeaderValue::from_static("conversation-edits"),
                );
                headers.insert("Editor-Version", HeaderValue::from_static("runne/1"));
                headers.insert(
                    "Editor-Plugin-Version",
                    HeaderValue::from_static("runne-responses/1"),
                );
                headers.insert("Copilot-Integration-Id", HeaderValue::from_static("runne"));
            }
            Self::Codex { account_id } => {
                let bearer =
                    Zeroizing::new([b"Bearer ".as_slice(), credential.as_slice()].concat());
                headers.insert(AUTHORIZATION, sensitive_header(&bearer)?);
                headers.insert("originator", HeaderValue::from_static("runne"));
                headers.insert(
                    "OpenAI-Beta",
                    HeaderValue::from_static("responses=experimental"),
                );
                headers.insert("accept", HeaderValue::from_static("text/event-stream"));
                let account_id = account_override.unwrap_or(account_id);
                if account_id.is_empty()
                    || account_id.len() > 256
                    || account_id
                        .chars()
                        .any(|c| c.is_control() || c.is_whitespace())
                {
                    return Err(AuthError::Credential);
                }
                let account =
                    HeaderValue::from_str(account_id).map_err(|_| AuthError::Credential)?;
                headers.insert("chatgpt-account-id", account);
            }
        }
        headers.remove(HOST);
        Ok(headers)
    }
}

fn sensitive_header(value: &Zeroizing<Vec<u8>>) -> Result<HeaderValue, AuthError> {
    let bytes = Bytes::from_owner(HeaderOwner {
        bytes: value.clone(),
    });
    let mut header = HeaderValue::from_maybe_shared(bytes).map_err(|_| AuthError::Credential)?;
    header.set_sensitive(true);
    Ok(header)
}

struct HeaderOwner {
    bytes: Zeroizing<Vec<u8>>,
}

impl AsRef<[u8]> for HeaderOwner {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for HeaderOwner {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn headers_keep_auth_sensitive_and_use_exact_scheme() {
        let token = Zeroizing::new(b"session-token".to_vec());
        let headers = ResponsesAuth::Codex {
            account_id: "acct_1".into(),
        }
        .headers(&token, "req-1")
        .unwrap();
        assert_eq!(
            headers.get(AUTHORIZATION).unwrap().to_str().unwrap(),
            "Bearer session-token"
        );
        assert!(headers.get(AUTHORIZATION).unwrap().is_sensitive());
        assert_eq!(headers.get("chatgpt-account-id").unwrap(), "acct_1");
        assert!(headers.get("api-key").is_none());
        assert_eq!(headers.get("originator").unwrap(), "runne");
        assert_eq!(
            headers.get("OpenAI-Beta").unwrap(),
            "responses=experimental"
        );
        let copilot = ResponsesAuth::CopilotSession
            .headers(&Zeroizing::new(b"session-token".to_vec()), "r")
            .unwrap();
        assert_eq!(copilot.get("X-Initiator").unwrap(), "user");
        assert_eq!(copilot.get("Openai-Intent").unwrap(), "conversation-edits");
        assert_eq!(copilot.get("Copilot-Integration-Id").unwrap(), "runne");
        assert!(
            ResponsesAuth::XaiBearer
                .headers(&Zeroizing::new(b"x\n".to_vec()), "r")
                .is_err()
        );
    }

    #[test]
    fn oauth_headers_use_the_envelope_account_and_reject_api_key_mixup() {
        let envelope = runne_provider_oauth::parse_stored_envelope(
            br#"{"schema":"runne.oauth-credential/v1","provider":"openai-codex","credential_version":4,"access_token":"oauth-access","refresh_token":"refresh","account_id":"envelope-acct","expires_at_unix_seconds":4102444800}"#,
            OAuthProvider::OpenAiCodex,
            4,
            1_700_000_000,
            60,
        )
        .unwrap();
        let auth = ResponsesAuth::Codex {
            account_id: "different-config-account".into(),
        };
        let headers = auth
            .headers_from_oauth_envelope(&envelope, "request")
            .unwrap();
        assert_eq!(headers.get("chatgpt-account-id").unwrap(), "envelope-acct");
        assert_eq!(headers.get(AUTHORIZATION).unwrap(), "Bearer oauth-access");
        assert!(
            ResponsesAuth::XaiBearer
                .headers_from_oauth_envelope(&envelope, "request")
                .is_err()
        );
    }
}
