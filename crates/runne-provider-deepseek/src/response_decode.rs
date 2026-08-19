use runne_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind, ProviderTerminalDisposition,
};

use crate::{
    DEEPSEEK_MAX_SSE_FRAME_BYTES, DEEPSEEK_MAX_TRANSPORT_CHUNKS, DeepSeekSseDecoder,
    DeepSeekStreamError, DeepSeekTransportResponse,
};

/// Decodes one bounded, already received `DeepSeek` response without network access.
///
/// # Errors
///
/// Returns an error when the response violates the pinned SSE contract.
pub fn decode_transport_response(
    response: &DeepSeekTransportResponse,
) -> Result<Vec<ProviderStreamEvent>, DeepSeekStreamError> {
    if response.chunks().len() > DEEPSEEK_MAX_TRANSPORT_CHUNKS {
        return Err(DeepSeekStreamError::StreamLimitExceeded);
    }
    if response.status() == 200 && response.content_type() == "text/event-stream" {
        let mut decoder = DeepSeekSseDecoder::default();
        for chunk in response.chunks() {
            decoder.push(chunk)?;
        }
        return decoder.finish();
    }
    if (200..300).contains(&response.status())
        || response.content_type() != "application/json"
        || response.chunks().is_empty()
    {
        return Err(DeepSeekStreamError::MalformedEvent);
    }
    let body = response.chunks().concat();
    if body.is_empty() || body.len() > DEEPSEEK_MAX_SSE_FRAME_BYTES {
        return Err(DeepSeekStreamError::StreamLimitExceeded);
    }
    super::sse::validate_remote_rejection(&body)?;
    [
        ProviderStreamEventKind::Started,
        ProviderStreamEventKind::UsageUnavailable,
        ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteFailed,
            reason: ProviderFinishReason::Error,
        },
    ]
    .into_iter()
    .enumerate()
    .map(|(sequence, kind)| {
        ProviderStreamEvent::new(sequence as u64, kind)
            .map_err(|_| DeepSeekStreamError::MalformedEvent)
    })
    .collect()
}
