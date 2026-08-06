use gocode_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind, ProviderTerminalDisposition,
};

use crate::{
    OPENAI_MAX_SSE_FRAME_BYTES, OPENAI_MAX_TRANSPORT_CHUNKS, OpenAiSseDecoder, OpenAiStreamError,
    OpenAiTransportResponse,
};

/// Decodes one bounded, already received `OpenAI` response without network access.
///
/// # Errors
///
/// Returns an error when the response violates the pinned SSE contract.
pub fn decode_transport_response(
    response: &OpenAiTransportResponse,
) -> Result<Vec<ProviderStreamEvent>, OpenAiStreamError> {
    if response.chunks().len() > OPENAI_MAX_TRANSPORT_CHUNKS {
        return Err(OpenAiStreamError::StreamLimitExceeded);
    }
    if response.status() == 200 && response.content_type() == "text/event-stream" {
        let mut decoder = OpenAiSseDecoder::default();
        for chunk in response.chunks() {
            decoder.push(chunk)?;
        }
        return decoder.finish();
    }
    if (200..300).contains(&response.status())
        || response.content_type() != "application/json"
        || response.chunks().is_empty()
    {
        return Err(OpenAiStreamError::MalformedEvent);
    }
    let body = response.chunks().concat();
    if body.is_empty() || body.len() > OPENAI_MAX_SSE_FRAME_BYTES {
        return Err(OpenAiStreamError::StreamLimitExceeded);
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
            .map_err(|_| OpenAiStreamError::MalformedEvent)
    })
    .collect()
}
