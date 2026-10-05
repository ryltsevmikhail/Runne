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
    D2ToolProposal,
    D2ToolLoopRound0,
    D2ToolLoopRound1,
    D2ToolLoopRound2,
    #[cfg_attr(
        test,
        expect(
            dead_code,
            reason = "The process fixture uses this route; unit tests exercise the stricter round-specific variants."
        )
    )]
    D2ToolLoop,
}

impl FixtureRequestKind {
    pub(super) fn for_request(self, index: usize) -> Option<Self> {
        match self {
            Self::D2ToolLoop => match index {
                0 => Some(Self::D2ToolLoopRound0),
                1 => Some(Self::D2ToolLoopRound1),
                2 => Some(Self::D2ToolLoopRound2),
                _ => None,
            },
            other => Some(other),
        }
    }
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
        FixtureRequestKind::D2ToolProposal
        | FixtureRequestKind::D2ToolLoopRound0
        | FixtureRequestKind::D2ToolLoopRound1
        | FixtureRequestKind::D2ToolLoopRound2
        | FixtureRequestKind::D2ToolLoop => {
            value
                .strip_prefix("gocode-d2-round-")
                .is_some_and(|digest| {
                    digest.len() == 32
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
        }
    }
}

#[cfg(test)]
#[path = "request_validation/tests.rs"]
mod tests;
