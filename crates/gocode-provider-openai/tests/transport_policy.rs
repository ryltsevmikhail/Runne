mod support;

use std::time::Duration;

use gocode_provider_openai::{
    OpenAiCredentialError, OpenAiCredentialMaterializer, OpenAiHttpTransport, OpenAiTransportError,
    OpenAiTransportPolicy,
};
use zeroize::Zeroizing;

struct FixedCredential;

impl OpenAiCredentialMaterializer for FixedCredential {
    fn materialize(&self) -> Result<Zeroizing<Vec<u8>>, OpenAiCredentialError> {
        Ok(Zeroizing::new(b"fixture-credential-never-print".to_vec()))
    }
}

#[test]
fn exact_transport_policy_is_https_post_without_proxy_redirect_or_retry() {
    let profile = support::profile();
    let policy = OpenAiTransportPolicy::for_profile(&profile).expect("exact policy");

    assert_eq!(policy.origin(), "https://api.openai.com");
    assert_eq!(policy.path(), "/v1/responses");
    assert_eq!(policy.method(), "POST");
    assert!(!policy.uses_ambient_proxy());
    assert!(!policy.follows_redirects());
    assert!(!policy.automatically_retries());
    assert_eq!(policy.max_frame_bytes(), 65_536);
    assert_eq!(policy.max_decoded_bytes(), 8 * 1024 * 1024);
    assert_eq!(policy.max_events(), 16_384);
    assert_eq!(policy.max_lines(), 65_536);
    assert_eq!(policy.max_transport_chunks(), 65_536);
    assert_eq!(policy.max_text_bytes(), 65_536);
    assert!(policy.connect_timeout() <= Duration::from_secs(10));
    assert!(policy.idle_timeout() <= Duration::from_secs(30));
    assert!(policy.total_timeout() <= Duration::from_mins(3));

    OpenAiHttpTransport::new(policy).expect("rustls transport");
}

#[test]
fn credential_and_transport_errors_never_expose_material() {
    let credential = FixedCredential.materialize().expect("credential");
    assert_eq!(credential.len(), 30);
    for error in [
        OpenAiCredentialError::Missing,
        OpenAiCredentialError::AccessDenied,
    ] {
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("fixture-credential-never-print"));
    }
    for error in [
        OpenAiTransportError::Unavailable,
        OpenAiTransportError::Timeout,
        OpenAiTransportError::TlsFailure,
        OpenAiTransportError::EndpointMismatch,
        OpenAiTransportError::ResponseRejected,
        OpenAiTransportError::StreamLimitExceeded,
    ] {
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("fixture-credential-never-print"));
        assert!(!diagnostic.contains("Authorization"));
    }
}
