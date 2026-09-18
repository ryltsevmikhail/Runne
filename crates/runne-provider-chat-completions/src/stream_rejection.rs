use runne_provider::{
    ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind, ProviderTerminalDisposition,
};
use serde_json::Value;

use crate::ChatCompletionsStreamError;

const MAX_FRAME_BYTES: usize = 65_536;

/// Normalizes a bounded non-2xx JSON response into closed terminal evidence.
///
/// # Errors
/// Returns `Malformed` for successful statuses, empty/oversized bodies, or invalid JSON.
pub fn normalize_json_rejection(
    status: u16,
    body: &[u8],
) -> Result<Vec<ProviderStreamEvent>, ChatCompletionsStreamError> {
    if (200..300).contains(&status) || body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(ChatCompletionsStreamError::Malformed);
    }
    let _: Value =
        serde_json::from_slice(body).map_err(|_| ChatCompletionsStreamError::Malformed)?;
    Ok(vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started)
            .map_err(|_| ChatCompletionsStreamError::Malformed)?,
        ProviderStreamEvent::new(1, ProviderStreamEventKind::UsageUnavailable)
            .map_err(|_| ChatCompletionsStreamError::Malformed)?,
        ProviderStreamEvent::new(
            2,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::RemoteFailed,
                reason: ProviderFinishReason::Error,
            },
        )
        .map_err(|_| ChatCompletionsStreamError::Malformed)?,
    ])
}
