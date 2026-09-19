use thiserror::Error;

/// OAuth provider whose endpoints are fixed by its protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthProvider {
    /// OpenAI Codex subscription.
    OpenAiCodex,
    /// GitHub Copilot subscription.
    GithubCopilot,
}

/// Exact operation permitted by a provider OAuth flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthOperation {
    /// Browser authorization.
    Authorize,
    /// Authorization-code exchange.
    TokenExchange,
    /// Refresh-token exchange.
    Refresh,
    /// Device user-code request.
    DeviceCode,
    /// Device-token polling.
    DeviceToken,
    /// Copilot session-token exchange.
    CopilotSession,
}

/// A validated, non-secret OAuth request descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthRequestDescriptor {
    /// Provider.
    pub provider: OAuthProvider,
    /// Operation.
    pub operation: OAuthOperation,
    /// Exact URL.
    pub url: String,
    /// HTTP method.
    pub method: &'static str,
    /// Content type when a body is present.
    pub content_type: Option<&'static str>,
}

/// Endpoint validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EndpointError {
    /// Domain was not an allowed GitHub host.
    #[error("OAuth endpoint host is not allowlisted")]
    Host,
    /// Endpoint contains unsafe URL characters.
    #[error("OAuth endpoint is malformed")]
    Malformed,
}

#[cfg(test)]
const OPENAI_AUTH: &str = "https://auth.openai.com";

/// Returns an exact descriptor for a fixed operation.
pub fn request_descriptor(
    provider: OAuthProvider,
    operation: OAuthOperation,
) -> Result<OAuthRequestDescriptor, EndpointError> {
    let (url, method, content_type) = match (provider, operation) {
        (OAuthProvider::OpenAiCodex, OAuthOperation::Authorize) => {
            ("https://auth.openai.com/oauth/authorize", "GET", None)
        }
        (OAuthProvider::OpenAiCodex, OAuthOperation::TokenExchange | OAuthOperation::Refresh) => (
            "https://auth.openai.com/oauth/token",
            "POST",
            Some("application/x-www-form-urlencoded"),
        ),
        (OAuthProvider::OpenAiCodex, OAuthOperation::DeviceCode) => (
            "https://auth.openai.com/api/accounts/deviceauth/usercode",
            "POST",
            Some("application/json"),
        ),
        (OAuthProvider::OpenAiCodex, OAuthOperation::DeviceToken) => (
            "https://auth.openai.com/api/accounts/deviceauth/token",
            "POST",
            Some("application/json"),
        ),
        (OAuthProvider::GithubCopilot, OAuthOperation::Authorize) => {
            return Err(EndpointError::Host);
        }
        (OAuthProvider::GithubCopilot, OAuthOperation::TokenExchange) => (
            "https://github.com/login/oauth/access_token",
            "POST",
            Some("application/x-www-form-urlencoded"),
        ),
        (
            OAuthProvider::GithubCopilot,
            OAuthOperation::Refresh | OAuthOperation::CopilotSession,
        ) => (
            "https://api.individual.githubcopilot.com/copilot_internal/v2/token",
            "POST",
            None,
        ),
        (OAuthProvider::GithubCopilot, OAuthOperation::DeviceCode) => (
            "https://github.com/login/device/code",
            "POST",
            Some("application/x-www-form-urlencoded"),
        ),
        (OAuthProvider::GithubCopilot, OAuthOperation::DeviceToken) => (
            "https://github.com/login/oauth/access_token",
            "POST",
            Some("application/x-www-form-urlencoded"),
        ),
        (OAuthProvider::OpenAiCodex, OAuthOperation::CopilotSession) => {
            return Err(EndpointError::Host);
        }
    };
    Ok(OAuthRequestDescriptor {
        provider,
        operation,
        url: url.to_owned(),
        method,
        content_type,
    })
}

/// Builds an enterprise Copilot descriptor after strict hostname validation.
pub fn enterprise_copilot_descriptor(
    domain: &str,
    operation: OAuthOperation,
) -> Result<OAuthRequestDescriptor, EndpointError> {
    let domain = validate_domain(domain)?;
    let url = match operation {
        OAuthOperation::DeviceCode => format!("https://{domain}/login/device/code"),
        OAuthOperation::DeviceToken => format!("https://{domain}/login/oauth/access_token"),
        OAuthOperation::Refresh | OAuthOperation::CopilotSession => {
            format!("https://api.{domain}/copilot_internal/v2/token")
        }
        OAuthOperation::Authorize | OAuthOperation::TokenExchange => {
            return Err(EndpointError::Host);
        }
    };
    Ok(OAuthRequestDescriptor {
        provider: OAuthProvider::GithubCopilot,
        operation,
        url,
        method: "POST",
        content_type: Some("application/x-www-form-urlencoded"),
    })
}

/// Validates a Copilot `proxy-ep` host and returns its fixed `api.` endpoint.
pub fn copilot_api_url_from_proxy(proxy: &str) -> Result<String, EndpointError> {
    let host = proxy.strip_prefix("proxy.").ok_or(EndpointError::Host)?;
    let host = validate_domain(host)?;
    Ok(format!("https://api.{host}"))
}

fn validate_domain(domain: &str) -> Result<String, EndpointError> {
    if domain.is_empty()
        || domain.len() > 253
        || !domain.is_ascii()
        || domain.contains(['/', ':', '?', '#', '@', '\\'])
    {
        return Err(EndpointError::Malformed);
    }
    let lower = domain.to_ascii_lowercase();
    let allowed = lower == "github.com"
        || lower.ends_with(".github.com")
        || lower == "individual.githubcopilot.com"
        || lower.ends_with(".githubcopilot.com");
    if !allowed
        || lower.split('.').any(|part| {
            part.is_empty()
                || part.len() > 63
                || part.starts_with('-')
                || part.ends_with('-')
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(EndpointError::Host);
    }
    Ok(lower)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_endpoints_cannot_cross_provider() {
        let d = request_descriptor(OAuthProvider::OpenAiCodex, OAuthOperation::Refresh).unwrap();
        assert!(d.url.starts_with(OPENAI_AUTH));
        assert!(!d.url.contains("github"));
        assert_eq!(
            request_descriptor(OAuthProvider::GithubCopilot, OAuthOperation::Refresh)
                .unwrap()
                .url,
            "https://api.individual.githubcopilot.com/copilot_internal/v2/token"
        );
        assert!(
            request_descriptor(OAuthProvider::OpenAiCodex, OAuthOperation::CopilotSession).is_err()
        );
    }
    #[test]
    fn proxy_is_strict() {
        assert_eq!(
            copilot_api_url_from_proxy("proxy.individual.githubcopilot.com").unwrap(),
            "https://api.individual.githubcopilot.com"
        );
        assert!(copilot_api_url_from_proxy("proxy.attacker.example").is_err());
        assert!(copilot_api_url_from_proxy("proxy.individual.githubcopilot.com/path").is_err());
    }
}
