use bytes::Bytes;
use core::future::Future;
use gocode_provider::DispatchError;
use reqwest::header::HeaderValue;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const OPENAI_RESPONSES_URL: &str = "https://api.openai.com/v1/responses";

pub(super) enum ResponseContract {
    Sse,
    JsonRejection(u16),
}

pub(super) fn accepted_response_contract(
    url: &str,
    status: u16,
    content_type: Option<&str>,
) -> Option<ResponseContract> {
    if url != OPENAI_RESPONSES_URL {
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

pub(super) fn append_bounded(target: &mut Vec<u8>, chunk: &[u8], maximum: usize) -> Result<(), ()> {
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

pub(super) fn record_chunk(count: &mut usize, maximum: usize) -> Result<(), ()> {
    let next = count.checked_add(1).ok_or(())?;
    if next > maximum {
        return Err(());
    }
    *count = next;
    Ok(())
}

pub(super) async fn wait_for_chunk<T>(
    idle: Duration,
    future: impl Future<Output = T>,
) -> Result<T, ()> {
    tokio::time::timeout(idle, future).await.map_err(|_| ())
}
