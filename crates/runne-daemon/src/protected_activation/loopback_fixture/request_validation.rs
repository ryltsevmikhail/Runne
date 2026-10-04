use body::Request;
use runne_daemon_openai_effect::FixtureRequestAuthenticator;
mod body;

const REQUIRED_HEADERS: [&str; 6] = [
    "host",
    "content-type",
    "content-length",
    "authorization",
    "x-client-request-id",
    "accept",
];
const EXPECTED_REQUEST_ID: &str = "gocode-provider-c436f15d42859a67270a2f39ff1c8508";
#[derive(Clone, Copy)]
pub(super) enum FixtureRequestKind {
    Pinned,
    ServicePointOfUse,
}

#[cfg(test)]
pub(crate) fn request_length(headers: &[u8]) -> Result<usize, ()> {
    request_length_for(headers, FixtureRequestKind::Pinned)
}

pub(super) fn request_length_for(headers: &[u8], kind: FixtureRequestKind) -> Result<usize, ()> {
    let fields = parse_headers(headers, kind)?;
    fields
        .iter()
        .find(|(name, _)| name == "content-length")
        .ok_or(())?
        .1
        .parse()
        .map_err(|_| ())
}

pub(crate) fn matches_expected_request(
    request: &[u8],
    authenticator: &FixtureRequestAuthenticator,
    kind: FixtureRequestKind,
) -> bool {
    let Some(headers_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let Ok(fields) = parse_headers(&request[..headers_end + 4], kind) else {
        return false;
    };
    let Ok(content_length) = fields
        .iter()
        .find(|(name, _)| name == "content-length")
        .ok_or(())
        .and_then(|(_, value)| value.parse::<usize>().map_err(|_| ()))
    else {
        return false;
    };
    if request.len() != headers_end + 4 + content_length {
        return false;
    }
    let authorization = fields
        .iter()
        .find(|(name, _)| name == "authorization")
        .map(|(_, value)| value.as_bytes());
    authorization.is_some_and(|value| authenticator.matches(value))
        && serde_json::from_slice::<Request>(&request[headers_end + 4..])
            .is_ok_and(|parsed| body::matches_expected_body(parsed, kind))
}

fn parse_headers(headers: &[u8], kind: FixtureRequestKind) -> Result<Vec<(String, &str)>, ()> {
    let headers = std::str::from_utf8(headers).map_err(|_| ())?;
    let mut lines = headers.split("\r\n");
    if lines.next() != Some("POST /v1/responses HTTP/1.1") {
        return Err(());
    }
    let mut fields = Vec::new();
    for line in lines {
        if line.is_empty() {
            if fields.len() != REQUIRED_HEADERS.len() {
                return Err(());
            }
            return Ok(fields);
        }
        if line.starts_with([' ', '\t']) || line.contains(['\n', '\t']) {
            return Err(());
        }
        let (name, value) = line.split_once(": ").ok_or(())?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.starts_with([' ', '\t'])
            || value.ends_with([' ', '\t'])
        {
            return Err(());
        }
        let name = name.to_ascii_lowercase();
        if name == "transfer-encoding"
            || !REQUIRED_HEADERS.contains(&name.as_str())
            || (name == "host" && value != "api.openai.com")
            || (name == "content-type" && value != "application/json")
            || (name == "accept" && value != "*/*")
            || (name == "x-client-request-id" && !request_id_matches(value, kind))
            || fields.iter().any(|(known, _)| *known == name)
        {
            return Err(());
        }
        fields.push((name, value));
    }
    Err(())
}

fn request_id_matches(value: &str, kind: FixtureRequestKind) -> bool {
    match kind {
        FixtureRequestKind::Pinned => value == EXPECTED_REQUEST_ID,
        FixtureRequestKind::ServicePointOfUse => value
            .strip_prefix("gocode-provider-")
            .is_some_and(|digest| {
                digest.len() == 32
                    && digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            }),
    }
}

#[cfg(test)]
mod tests {
    use super::{FixtureRequestKind, request_length, request_length_for};

    fn valid_headers() -> String {
        concat!(
            "host: api.openai.com\r\n",
            "content-type: application/json\r\n",
            "content-length: 0\r\n",
            "authorization: Bearer x\r\n",
            "x-client-request-id: gocode-provider-c436f15d42859a67270a2f39ff1c8508\r\n",
            "accept: */*\r\n",
        )
        .to_owned()
    }

    fn request(headers: &str) -> String {
        format!("POST /v1/responses HTTP/1.1\r\n{headers}\r\n")
    }

    #[test]
    fn rejects_missing_duplicate_unknown_and_transfer_headers() {
        let headers = valid_headers();
        for invalid in [
            headers.replace("accept: */*\r\n", ""),
            format!("{headers}host: api.openai.com\r\n"),
            format!("{headers}accept-encoding: gzip\r\n"),
            format!("{headers}transfer-encoding: chunked\r\n"),
        ] {
            assert!(request_length(request(&invalid).as_bytes()).is_err());
        }
    }

    #[test]
    fn accepts_exact_six_required_headers_with_exact_accept_value() {
        assert_eq!(request_length(request(&valid_headers()).as_bytes()), Ok(0));
    }

    #[test]
    fn accepts_the_pre_rename_provider_idempotency_vector() {
        let headers = concat!(
            "host: api.openai.com\r\n",
            "content-type: application/json\r\n",
            "content-length: 0\r\n",
            "authorization: Bearer x\r\n",
            "x-client-request-id: gocode-provider-c436f15d42859a67270a2f39ff1c8508\r\n",
            "accept: */*\r\n",
        );
        assert_eq!(request_length(request(headers).as_bytes()), Ok(0));
    }

    #[test]
    fn service_point_of_use_accepts_only_canonical_dynamic_request_ids() {
        let headers = valid_headers();
        let dynamic = headers.replace(
            super::EXPECTED_REQUEST_ID,
            "gocode-provider-0123456789abcdef0123456789abcdef",
        );
        assert_eq!(
            request_length_for(
                request(&dynamic).as_bytes(),
                FixtureRequestKind::ServicePointOfUse,
            ),
            Ok(0)
        );
        for invalid in [
            dynamic.replace("gocode-provider-", "runne-provider-"),
            dynamic.replace('f', "F"),
            dynamic.replace("0123456789abcdef", "0123456789abcde"),
        ] {
            assert!(
                request_length_for(
                    request(&invalid).as_bytes(),
                    FixtureRequestKind::ServicePointOfUse,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_non_exact_accept_value() {
        let headers = valid_headers().replace("accept: */*", "accept: application/json");
        assert!(request_length(request(&headers).as_bytes()).is_err());
    }

    #[test]
    fn rejects_non_exact_host_content_type_and_request_id() {
        let headers = valid_headers();
        for invalid in [
            headers.replace("host: api.openai.com", "host: api.example.com"),
            headers.replace("content-type: application/json", "content-type: text/plain"),
            headers.replace(
                "gocode-provider-c436f15d42859a67270a2f39ff1c8508",
                "other-provider-0123456789abcdef0123456789abcdef",
            ),
            headers.replace(
                "gocode-provider-c436f15d42859a67270a2f39ff1c8508",
                "runne-provider-cb1a6843c5c332cda4a0f78cc9d606ce",
            ),
            headers.replace(
                "gocode-provider-c436f15d42859a67270a2f39ff1c8508",
                "gocode-provider-0123456789abcdef0123456789abcde",
            ),
            headers.replace(
                "gocode-provider-c436f15d42859a67270a2f39ff1c8508",
                "gocode-provider-0123456789abcdef0123456789abcdeF",
            ),
        ] {
            assert!(request_length(request(&invalid).as_bytes()).is_err());
        }
    }

    #[test]
    fn rejects_invalid_header_separator_and_ows() {
        let headers = valid_headers();
        for invalid in [
            headers.replace("host: api.openai.com", "host:api.openai.com"),
            headers.replace("host: api.openai.com", "host:  api.openai.com"),
            headers.replace("host: api.openai.com", "host:\tapi.openai.com"),
            headers.replace("host: api.openai.com", " host: api.openai.com"),
            headers.replace("host: api.openai.com", "host: api.openai.com "),
        ] {
            assert!(request_length(request(&invalid).as_bytes()).is_err());
        }
    }
}
