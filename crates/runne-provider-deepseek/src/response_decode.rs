use runne_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind, ProviderTerminalDisposition,
};

use crate::decode_diagnostic::{
    DeepSeekDecodeDiagnostic, DeepSeekDecodeEventKind, DeepSeekDecodeField, DeepSeekDecodeIssue,
    DeepSeekDecodePhase, DeepSeekDecodeSchemaNode,
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
    decode_transport_response_inner(response).0
}

#[cfg(feature = "qualification-diagnostics")]
/// Decodes the pinned response while retaining a redacted fixed-code failure location.
///
/// The diagnostic contains only closed enum values; this does not alter decoder acceptance.
pub fn decode_transport_response_with_diagnostic(
    response: &DeepSeekTransportResponse,
) -> (
    Result<Vec<ProviderStreamEvent>, DeepSeekStreamError>,
    Option<DeepSeekDecodeDiagnostic>,
) {
    decode_transport_response_inner(response)
}

fn decode_transport_response_inner(
    response: &DeepSeekTransportResponse,
) -> (
    Result<Vec<ProviderStreamEvent>, DeepSeekStreamError>,
    Option<DeepSeekDecodeDiagnostic>,
) {
    if response.chunks().len() > DEEPSEEK_MAX_TRANSPORT_CHUNKS {
        return (
            Err(DeepSeekStreamError::StreamLimitExceeded),
            Some(diagnostic(
                DeepSeekDecodePhase::SseFrame,
                DeepSeekDecodeSchemaNode::SseFrame,
                DeepSeekDecodeField::Data,
                DeepSeekDecodeIssue::BoundExceeded,
            )),
        );
    }
    if response.status() == 200 && response.content_type() == "text/event-stream" {
        let mut decoder = DeepSeekSseDecoder::default();
        for chunk in response.chunks() {
            if let Err(error) = decoder.push(chunk) {
                let detail = decoder.failure_diagnostic();
                return (Err(error), detail);
            }
        }
        return decoder.finish_with_diagnostic();
    }
    if (200..300).contains(&response.status())
        || response.content_type() != "application/json"
        || response.chunks().is_empty()
    {
        return (
            Err(DeepSeekStreamError::MalformedEvent),
            Some(diagnostic(
                DeepSeekDecodePhase::SseFrame,
                DeepSeekDecodeSchemaNode::SseFrame,
                DeepSeekDecodeField::Data,
                DeepSeekDecodeIssue::ResponseContractRejected,
            )),
        );
    }
    let body = response.chunks().concat();
    if body.is_empty() || body.len() > DEEPSEEK_MAX_SSE_FRAME_BYTES {
        return (
            Err(DeepSeekStreamError::StreamLimitExceeded),
            Some(diagnostic(
                DeepSeekDecodePhase::SseFrame,
                DeepSeekDecodeSchemaNode::RemoteErrorResponse,
                DeepSeekDecodeField::Data,
                DeepSeekDecodeIssue::BoundExceeded,
            )),
        );
    }
    if let Err(error) = super::sse::validate_remote_rejection(&body) {
        return (
            Err(error),
            Some(diagnostic(
                DeepSeekDecodePhase::EventSchema,
                DeepSeekDecodeSchemaNode::RemoteErrorResponse,
                DeepSeekDecodeField::Error,
                DeepSeekDecodeIssue::ResponseContractRejected,
            )),
        );
    }
    let result = [
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
    .collect();
    (result, None)
}

const fn diagnostic(
    phase: DeepSeekDecodePhase,
    node: DeepSeekDecodeSchemaNode,
    field: DeepSeekDecodeField,
    issue: DeepSeekDecodeIssue,
) -> DeepSeekDecodeDiagnostic {
    DeepSeekDecodeDiagnostic {
        phase,
        event: DeepSeekDecodeEventKind::Unknown,
        node,
        field,
        issue,
    }
}

#[cfg(all(test, feature = "qualification-diagnostics"))]
#[path = "response_decode_tests.rs"]
mod tests;
