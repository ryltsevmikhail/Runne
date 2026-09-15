use bytes::Bytes;
use core::future::Future;
use reqwest::header::HeaderValue;
use runne_provider::DispatchError;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const MAX_TRANSPORT_CHUNKS: usize = 4_096;
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) enum ResponseContract {
    Sse,
    JsonRejection(u16),
}

pub(super) fn accepted_response_contract(
    expected_url: &str,
    url: &str,
    status: u16,
    content_type: Option<&str>,
) -> Option<ResponseContract> {
    if url != expected_url {
        return None;
    }
    match content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim)
    {
        Some("text/event-stream") if status == 200 => Some(ResponseContract::Sse),
        Some("application/json") if !(200..300).contains(&status) => {
            Some(ResponseContract::JsonRejection(status))
        }
        _ => None,
    }
}

pub(super) fn bearer_header(credential: &Zeroizing<Vec<u8>>) -> Result<HeaderValue, DispatchError> {
    let bytes = Bytes::from_owner(AuthorizationOwner::new(credential));
    let mut header =
        HeaderValue::from_maybe_shared(bytes).map_err(|_| DispatchError::MaybeDispatched)?;
    header.set_sensitive(true);
    Ok(header)
}

struct AuthorizationOwner {
    wire: Zeroizing<Vec<u8>>,
}

impl AuthorizationOwner {
    fn new(credential: &Zeroizing<Vec<u8>>) -> Self {
        let mut wire = Zeroizing::new(Vec::with_capacity(b"Bearer ".len() + credential.len()));
        wire.extend_from_slice(b"Bearer ");
        wire.extend_from_slice(credential);
        Self { wire }
    }
}

impl AsRef<[u8]> for AuthorizationOwner {
    fn as_ref(&self) -> &[u8] {
        &self.wire
    }
}

impl Drop for AuthorizationOwner {
    fn drop(&mut self) {
        self.wire.zeroize();
    }
}

pub(crate) fn append_bounded(target: &mut Vec<u8>, chunk: &[u8], maximum: usize) -> Result<(), ()> {
    if target
        .len()
        .checked_add(chunk.len())
        .is_none_or(|total| total > maximum)
    {
        return Err(());
    }
    target.extend_from_slice(chunk);
    Ok(())
}

pub(crate) fn record_chunk(count: &mut usize) -> Result<(), ()> {
    *count = count.checked_add(1).ok_or(())?;
    (*count <= MAX_TRANSPORT_CHUNKS).then_some(()).ok_or(())
}

pub(crate) async fn wait_for_chunk<T>(future: impl Future<Output = T>) -> Result<T, ()> {
    tokio::time::timeout(IDLE_TIMEOUT, future)
        .await
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_contract_requires_exact_url_and_media_type() {
        assert!(matches!(
            accepted_response_contract(
                "https://provider.example/v1/chat/completions",
                "https://provider.example/v1/chat/completions",
                200,
                Some("text/event-stream; charset=utf-8"),
            ),
            Some(ResponseContract::Sse)
        ));
        assert!(
            accepted_response_contract(
                "https://provider.example/v1/chat/completions",
                "https://other.example/v1/chat/completions",
                200,
                Some("text/event-stream"),
            )
            .is_none()
        );
        assert!(
            accepted_response_contract(
                "https://provider.example/v1/chat/completions",
                "https://provider.example/v1/chat/completions",
                200,
                Some("application/json"),
            )
            .is_none()
        );
    }

    #[test]
    fn response_body_and_chunk_count_are_bounded() {
        let mut body = Vec::new();
        assert!(append_bounded(&mut body, b"ok", 2).is_ok());
        assert!(append_bounded(&mut body, b"!", 2).is_err());
        let mut count = 0;
        for _ in 0..MAX_TRANSPORT_CHUNKS {
            assert!(record_chunk(&mut count).is_ok());
        }
        assert!(record_chunk(&mut count).is_err());
    }
}
