use runne_provider_native_wire::NativeWireProfile;

use crate::{NativeAuthDescriptor, NativeEffectError, TrustedNativeEndpoint};

pub(crate) fn safe_base(value: &str) -> Result<String, NativeEffectError> {
    let url: reqwest::Url = value
        .parse()
        .map_err(|_| NativeEffectError::UnsafeEndpoint)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(NativeEffectError::UnsafeEndpoint);
    }
    Ok(value.trim_end_matches('/').to_owned())
}

pub(crate) fn route_segment(value: &str) -> Result<String, NativeEffectError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(NativeEffectError::InvalidDescriptor);
    }
    Ok(value.to_owned())
}

pub(crate) fn encode_segment(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            result.push(char::from(byte));
        } else {
            result.push('%');
            result.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
            result.push(char::from(b"0123456789ABCDEF"[(byte & 0x0f) as usize]));
        }
    }
    result
}

pub(crate) fn validate_route(
    profile: &NativeWireProfile,
    endpoint: &TrustedNativeEndpoint,
    auth: NativeAuthDescriptor,
) -> Result<(), NativeEffectError> {
    match (profile, endpoint, auth) {
        (
            NativeWireProfile::Anthropic(profile),
            TrustedNativeEndpoint::Anthropic { base_url },
            auth,
        ) if anthropic_route(profile.provider_id(), base_url, auth) => Ok(()),
        (
            NativeWireProfile::Gemini(profile),
            TrustedNativeEndpoint::Gemini { base_url },
            NativeAuthDescriptor::GeminiApiKey,
        ) if profile.provider_id() == "google"
            && base_url == "https://generativelanguage.googleapis.com/v1beta" =>
        {
            Ok(())
        }
        (
            NativeWireProfile::Gemini(profile),
            TrustedNativeEndpoint::Vertex {
                base_url,
                project,
                location,
            },
            NativeAuthDescriptor::VertexBearer,
        ) if profile.provider_id() == "google-vertex"
            && vertex_route(base_url, project, location) =>
        {
            Ok(())
        }
        _ => Err(NativeEffectError::AuthMismatch),
    }
}

fn anthropic_route(provider: &str, base_url: &str, auth: NativeAuthDescriptor) -> bool {
    let expected = match provider {
        "anthropic" => (
            "https://api.anthropic.com",
            NativeAuthDescriptor::AnthropicApiKey,
        ),
        "kimi-coding" => ("https://api.kimi.com/coding", NativeAuthDescriptor::Bearer),
        "minimax" => (
            "https://api.minimax.io/anthropic",
            NativeAuthDescriptor::AnthropicApiKey,
        ),
        "minimax-cn" => (
            "https://api.minimaxi.com/anthropic",
            NativeAuthDescriptor::AnthropicApiKey,
        ),
        "vercel-ai-gateway" => ("https://ai-gateway.vercel.sh", NativeAuthDescriptor::Bearer),
        _ => return false,
    };
    base_url == expected.0 && auth == expected.1
}

fn vertex_route(base_url: &str, project: &str, location: &str) -> bool {
    let host = format!("https://{location}-aiplatform.googleapis.com");
    base_url == host && valid_cloud_project(project) && valid_cloud_location(location)
}

fn valid_cloud_project(value: &str) -> bool {
    (6..=30).contains(&value.len())
        && value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_cloud_location(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}
