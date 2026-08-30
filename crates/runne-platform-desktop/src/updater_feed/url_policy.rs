use reqwest::Url;

use super::UpdateFeedError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransportPolicy {
    Https,
    #[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
    DevLoopback,
}

pub(super) fn parse_url(value: &str, policy: TransportPolicy) -> Result<Url, UpdateFeedError> {
    let url = Url::parse(value).map_err(|_| UpdateFeedError::InvalidUrl)?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(UpdateFeedError::InvalidUrl);
    }
    if url.scheme() == "https" {
        return Ok(url);
    }
    #[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
    if policy == TransportPolicy::DevLoopback && exact_loopback(value, &url) {
        return Ok(url);
    }
    let _ = policy;
    Err(UpdateFeedError::InvalidUrl)
}

#[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
fn exact_loopback(value: &str, url: &Url) -> bool {
    let Some(remainder) = value.strip_prefix("http://127.0.0.1") else {
        return false;
    };
    let boundary = remainder
        .as_bytes()
        .first()
        .is_none_or(|byte| matches!(byte, b':' | b'/' | b'?'));
    boundary && url.scheme() == "http" && url.host_str() == Some("127.0.0.1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_policy_is_https_only() {
        assert!(
            parse_url(
                "https://updates.example.test/feed.json",
                TransportPolicy::Https
            )
            .is_ok()
        );
        assert!(parse_url("http://127.0.0.1/feed.json", TransportPolicy::Https).is_err());
    }

    #[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
    #[test]
    fn dev_policy_accepts_only_exact_ipv4_loopback() {
        assert!(
            parse_url(
                "http://127.0.0.1:8080/feed.json",
                TransportPolicy::DevLoopback
            )
            .is_ok()
        );
        for value in [
            "http://localhost/feed.json",
            "http://[::1]/feed.json",
            "http://127.0.0.2/feed.json",
            "http://0.0.0.0/feed.json",
            "http://user@127.0.0.1/feed.json",
            "http://127.0.0.1/feed.json#fragment",
            "http://2130706433/feed.json",
        ] {
            assert!(
                parse_url(value, TransportPolicy::DevLoopback).is_err(),
                "{value}"
            );
        }
    }
}
