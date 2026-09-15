use reqwest::header::{AUTHORIZATION, HeaderName};

/// Header used to carry a bearer credential to a fixed Chat endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChatCompletionsAuthHeader {
    /// Standard HTTP authorization header.
    Authorization,
    /// Cloudflare AI Gateway's explicit BYOK header.
    CloudflareAiGateway,
}

pub(crate) fn header_name(header: ChatCompletionsAuthHeader) -> HeaderName {
    match header {
        ChatCompletionsAuthHeader::Authorization => AUTHORIZATION,
        ChatCompletionsAuthHeader::CloudflareAiGateway => {
            HeaderName::from_static("cf-aig-authorization")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_uses_distinct_sensitive_header_name() {
        assert_eq!(
            header_name(ChatCompletionsAuthHeader::CloudflareAiGateway).as_str(),
            "cf-aig-authorization"
        );
        assert_eq!(
            header_name(ChatCompletionsAuthHeader::Authorization),
            AUTHORIZATION
        );
    }
}
